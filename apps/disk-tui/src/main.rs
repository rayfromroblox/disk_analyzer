use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use crossbeam_channel::{Receiver, unbounded};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use disk_core::{
    CancellationToken, EntryKind, NodeId, ScanConfig, ScanProgress, ScanResult, SizeMetric,
    format_bytes, scan,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, Padding, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};

#[derive(Debug, Parser)]
#[command(
    name = "disk-analyzer-tui",
    version,
    about = "Interactive terminal disk usage analyzer"
)]
struct Args {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,

    #[arg(long)]
    follow_links: bool,

    #[arg(long)]
    cross_filesystems: bool,

    #[arg(long)]
    count_hard_links: bool,

    #[arg(long, value_enum, default_value_t = Metric::Allocated)]
    size: Metric,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Metric {
    Logical,
    Allocated,
}

impl From<Metric> for SizeMetric {
    fn from(value: Metric) -> Self {
        match value {
            Metric::Logical => Self::Logical,
            Metric::Allocated => Self::Allocated,
        }
    }
}

enum WorkerMessage {
    Progress(ScanProgress),
    Finished(Result<ScanResult, String>),
}

struct App {
    config: ScanConfig,
    cancellation: CancellationToken,
    receiver: Receiver<WorkerMessage>,
    progress: ScanProgress,
    result: Option<ScanResult>,
    error: Option<String>,
    current_id: NodeId,
    visible: Vec<NodeId>,
    table_state: TableState,
    metric: SizeMetric,
    search: String,
    editing_search: bool,
    show_help: bool,
    show_errors: bool,
    should_quit: bool,
}

impl App {
    fn new(config: ScanConfig, metric: SizeMetric) -> Self {
        let (receiver, cancellation) = start_worker(config.clone());
        let progress = initial_progress(&config.root);
        Self {
            config,
            cancellation,
            receiver,
            progress,
            result: None,
            error: None,
            current_id: 0,
            visible: Vec::new(),
            table_state: TableState::default().with_selected(0),
            metric,
            search: String::new(),
            editing_search: false,
            show_help: false,
            show_errors: false,
            should_quit: false,
        }
    }

    fn scanning(&self) -> bool {
        self.result.is_none() && self.error.is_none() && !self.progress.finished
    }

    fn receive_worker_messages(&mut self) {
        while let Ok(message) = self.receiver.try_recv() {
            match message {
                WorkerMessage::Progress(progress) => self.progress = progress,
                WorkerMessage::Finished(Ok(result)) => {
                    self.current_id = result.root_id;
                    self.result = Some(result);
                    self.refresh_visible();
                }
                WorkerMessage::Finished(Err(error)) => self.error = Some(error),
            }
        }
    }

    fn refresh_visible(&mut self) {
        let Some(result) = self.result.as_ref() else {
            self.visible.clear();
            return;
        };
        let query = self.search.to_lowercase();
        let metric = self.metric;
        let mut visible: Vec<_> = result
            .children_of(self.current_id)
            .filter(|node| query.is_empty() || node.name.to_lowercase().contains(&query))
            .map(|node| node.id)
            .collect();
        visible.sort_unstable_by(|left, right| {
            let left = result.node(*left).expect("child index must be valid");
            let right = result.node(*right).expect("child index must be valid");
            right
                .size(metric)
                .cmp(&left.size(metric))
                .then_with(|| {
                    right
                        .kind
                        .eq(&EntryKind::Directory)
                        .cmp(&left.kind.eq(&EntryKind::Directory))
                })
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        self.visible = visible;

        let selected = self
            .table_state
            .selected()
            .unwrap_or(0)
            .min(self.visible.len().saturating_sub(1));
        self.table_state
            .select((!self.visible.is_empty()).then_some(selected));
    }

    fn selected_id(&self) -> Option<NodeId> {
        self.table_state
            .selected()
            .and_then(|selected| self.visible.get(selected))
            .copied()
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            self.table_state.select(None);
            return;
        }
        let current = self.table_state.selected().unwrap_or(0) as isize;
        let last = self.visible.len().saturating_sub(1) as isize;
        self.table_state
            .select(Some((current + delta).clamp(0, last) as usize));
    }

    fn enter_selected(&mut self) {
        let Some(id) = self.selected_id() else {
            return;
        };
        let is_directory = self
            .result
            .as_ref()
            .and_then(|result| result.node(id))
            .is_some_and(|node| node.kind == EntryKind::Directory);
        if is_directory {
            self.current_id = id;
            self.search.clear();
            self.table_state.select(Some(0));
            self.refresh_visible();
        }
    }

    fn go_parent(&mut self) {
        let parent = self
            .result
            .as_ref()
            .and_then(|result| result.node(self.current_id))
            .and_then(|node| node.parent_id);
        if let Some(parent) = parent {
            self.current_id = parent;
            self.search.clear();
            self.table_state.select(Some(0));
            self.refresh_visible();
        }
    }

    fn open_selected(&self) {
        if let (Some(result), Some(id)) = (&self.result, self.selected_id())
            && let Some(path) = result.path_for(id)
        {
            let _ = open::that(path);
        }
    }

    fn restart(&mut self) {
        self.cancellation.cancel();
        let (receiver, cancellation) = start_worker(self.config.clone());
        self.receiver = receiver;
        self.cancellation = cancellation;
        self.progress = initial_progress(&self.config.root);
        self.result = None;
        self.error = None;
        self.visible.clear();
        self.search.clear();
        self.table_state.select(Some(0));
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.cancellation.cancel();
            self.should_quit = true;
            return;
        }

        if self.editing_search {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.editing_search = false,
                KeyCode::Backspace => {
                    self.search.pop();
                    self.refresh_visible();
                }
                KeyCode::Char(character) => {
                    self.search.push(character);
                    self.refresh_visible();
                }
                _ => {}
            }
            return;
        }

        if self.show_help || self.show_errors {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                    self.show_help = false;
                    self.show_errors = false;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.cancellation.cancel();
                self.should_quit = true;
            }
            KeyCode::Char('c') if self.scanning() => self.cancellation.cancel(),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('e') => self.show_errors = true,
            KeyCode::Char('/') if self.result.is_some() => self.editing_search = true,
            KeyCode::Char('s') if self.result.is_some() => {
                self.metric = match self.metric {
                    SizeMetric::Logical => SizeMetric::Allocated,
                    SizeMetric::Allocated => SizeMetric::Logical,
                };
                self.refresh_visible();
            }
            KeyCode::Char('r') => self.restart(),
            KeyCode::Char('o') => self.open_selected(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::Home => self.table_state.select(Some(0)),
            KeyCode::End if !self.visible.is_empty() => {
                self.table_state.select(Some(self.visible.len() - 1));
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.enter_selected(),
            KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') | KeyCode::Esc => {
                self.go_parent();
            }
            _ => {}
        }
    }
}

fn initial_progress(path: &std::path::Path) -> ScanProgress {
    ScanProgress {
        files: 0,
        directories: 0,
        symlinks: 0,
        logical_bytes: 0,
        allocated_bytes: 0,
        errors: 0,
        elapsed_ms: 0,
        current_path: path.to_string_lossy().into_owned(),
        canceled: false,
        finished: false,
    }
}

fn start_worker(config: ScanConfig) -> (Receiver<WorkerMessage>, CancellationToken) {
    let (sender, receiver) = unbounded();
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    std::thread::spawn(move || {
        let progress_sender = sender.clone();
        let result = scan(config, worker_cancellation, move |progress| {
            let _ = progress_sender.send(WorkerMessage::Progress(progress.clone()));
        })
        .map_err(|error| error.to_string());
        let _ = sender.send(WorkerMessage::Finished(result));
    });
    (receiver, cancellation)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = ScanConfig::new(args.path);
    config.threads = args.threads;
    config.follow_symlinks = args.follow_links;
    config.stay_on_filesystem = !args.cross_filesystems;
    config.deduplicate_hard_links = !args.count_hard_links;

    let mut app = App::new(config, args.size.into());
    let mut terminal = setup_terminal()?;
    let result = run(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    while !app.should_quit {
        app.receive_worker_messages();
        terminal.draw(|frame| draw(frame, app))?;
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            app.handle_key(key);
        }
    }
    Ok(())
}

fn draw(frame: &mut Frame, app: &mut App) {
    let page = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());

    draw_header(frame, page[0], app);
    if app.scanning() {
        draw_scanning(frame, page[1], app);
    } else if let Some(error) = &app.error {
        let paragraph = Paragraph::new(error.as_str())
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(" Scan failed ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .padding(Padding::uniform(1)),
            );
        frame.render_widget(paragraph, page[1]);
    } else {
        draw_results(frame, page[1], app);
    }
    draw_footer(frame, page[2], app);

    if app.show_help {
        draw_help(frame);
    } else if app.show_errors {
        draw_errors(frame, app);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let status = if app.scanning() {
        Span::styled(
            " SCANNING ",
            Style::default().bg(Color::Yellow).fg(Color::Black),
        )
    } else if app.error.is_some() {
        Span::styled(" ERROR ", Style::default().bg(Color::Red).fg(Color::White))
    } else if app.progress.canceled {
        Span::styled(
            " PARTIAL ",
            Style::default().bg(Color::Yellow).fg(Color::Black),
        )
    } else {
        Span::styled(
            " COMPLETE ",
            Style::default().bg(Color::Green).fg(Color::Black),
        )
    };
    let title = Line::from(vec![
        Span::styled(
            " DISK ANALYZER ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        status,
    ]);
    frame.render_widget(
        Paragraph::new(title)
            .block(Block::default().borders(Borders::BOTTOM))
            .alignment(Alignment::Left),
        area,
    );
}

fn draw_scanning(frame: &mut Frame, area: Rect, app: &App) {
    let inner = centered_rect(78, 80, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(3),
        ])
        .split(inner);

    let pulse = ((app.progress.elapsed_ms / 80) % 100) as u16;
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .title(" Reading filesystem ")
                    .borders(Borders::ALL),
            )
            .gauge_style(Style::default().fg(Color::Cyan))
            .percent(pulse)
            .label("discovering entries"),
        rows[0],
    );

    let stats = Line::from(vec![
        Span::styled(
            format!("{:>12}", app.progress.files),
            Style::default().fg(Color::White).bold(),
        ),
        Span::raw(" files   "),
        Span::styled(
            format!("{:>10}", app.progress.directories),
            Style::default().fg(Color::White).bold(),
        ),
        Span::raw(" dirs   "),
        Span::styled(
            format_bytes(app.progress.logical_bytes),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::raw(" logical   "),
        Span::styled(
            format_bytes(app.progress.allocated_bytes),
            Style::default().fg(Color::Magenta).bold(),
        ),
        Span::raw(" allocated"),
    ]);
    frame.render_widget(
        Paragraph::new(stats)
            .alignment(Alignment::Center)
            .block(Block::default().padding(Padding::vertical(1))),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "Elapsed {:.1}s  •  {} errors  •  press q to cancel",
            app.progress.elapsed_ms as f64 / 1000.0,
            app.progress.errors
        ))
        .alignment(Alignment::Center)
        .fg(Color::DarkGray),
        rows[2],
    );
    frame.render_widget(
        Paragraph::new(app.progress.current_path.as_str())
            .wrap(Wrap { trim: false })
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .title(" Current path ")
                    .borders(Borders::ALL),
            ),
        rows[3],
    );
}

fn draw_results(frame: &mut Frame, area: Rect, app: &mut App) {
    let Some(result) = app.result.as_ref() else {
        return;
    };
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(5)])
        .split(area);
    let summary = &result.summary;
    let path = result
        .display_path(app.current_id)
        .unwrap_or_else(|| summary.root.clone());
    let metric_name = match app.metric {
        SizeMetric::Logical => "logical",
        SizeMetric::Allocated => "allocated",
    };
    let search = if app.editing_search {
        format!("  Search: {}▌", app.search)
    } else if app.search.is_empty() {
        String::new()
    } else {
        format!("  Search: {}", app.search)
    };
    let summary_text = vec![
        Line::from(vec![
            Span::styled(path, Style::default().fg(Color::Cyan).bold()),
            Span::styled(search, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(format!(
            "{} files  •  {} directories  •  {} logical  •  {} allocated  •  {} errors  •  sorting by {metric_name}",
            summary.files,
            summary.directories,
            format_bytes(summary.logical_bytes),
            format_bytes(summary.allocated_bytes),
            summary.errors,
        )),
    ];
    frame.render_widget(
        Paragraph::new(summary_text).block(
            Block::default()
                .title(" Location ")
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1)),
        ),
        sections[0],
    );

    let parent_size = result
        .node(app.current_id)
        .map(|node| node.size(app.metric))
        .unwrap_or(0);
    let rows = app
        .visible
        .iter()
        .filter_map(|id| result.node(*id))
        .map(|node| {
            let icon = match node.kind {
                EntryKind::Directory => "DIR",
                EntryKind::File => "FILE",
                EntryKind::Symlink => "LINK",
                EntryKind::Other => "OTHER",
            };
            let percent = if parent_size == 0 {
                0.0
            } else {
                node.size(app.metric) as f64 * 100.0 / parent_size as f64
            };
            Row::new(vec![
                Cell::from(icon),
                Cell::from(node.name.clone()),
                Cell::from(format_bytes(node.logical_size)),
                Cell::from(format_bytes(node.allocated_size)),
                Cell::from(node.file_count.to_string()),
                Cell::from(node.directory_count.to_string()),
                Cell::from(format!("{percent:.1}%")),
            ])
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Min(20),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new([
            "TYPE",
            "NAME",
            "LOGICAL",
            "ALLOCATED",
            "FILES",
            "DIRS",
            "% PARENT",
        ])
        .style(Style::default().fg(Color::Cyan).bold())
        .bottom_margin(1),
    )
    .block(
        Block::default()
            .title(format!(" Contents ({}) ", app.visible.len()))
            .borders(Borders::ALL),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(24, 55, 72))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, sections[1], &mut app.table_state);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let shortcuts = if app.editing_search {
        "type to filter  •  Enter accept  •  Esc stop editing"
    } else if app.scanning() {
        "c cancel and keep partial results  •  q cancel and quit  •  ? help"
    } else {
        "↑↓/jk move  •  Enter open dir  •  Backspace up  •  / search  •  s size  •  o open  •  r rescan  •  e errors  •  ? help  •  q quit"
    };
    frame.render_widget(
        Paragraph::new(shortcuts)
            .alignment(Alignment::Center)
            .fg(Color::DarkGray),
        area,
    );
}

fn draw_help(frame: &mut Frame) {
    let area = centered_rect(62, 62, frame.area());
    frame.render_widget(Clear, area);
    let help = [
        "Navigation",
        "  ↑/↓ or j/k       Move selection",
        "  Enter or l       Enter selected directory",
        "  Backspace or h   Go to parent directory",
        "  Home/End         Jump to first/last entry",
        "",
        "Actions",
        "  /                Filter current directory",
        "  s                Toggle logical/allocated sorting",
        "  o                Open selected entry with the OS",
        "  e                Show scan errors",
        "  r                Rescan",
        "  c                Cancel and keep partial results",
        "  q                Quit (and cancel an active scan)",
        "",
        "Press Esc, q, or ? to close this help.",
    ];
    frame.render_widget(
        Paragraph::new(help.join("\n"))
            .block(
                Block::default()
                    .title(" Help ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .padding(Padding::uniform(1)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_errors(frame: &mut Frame, app: &App) {
    let area = centered_rect(82, 75, frame.area());
    frame.render_widget(Clear, area);
    let text = app
        .result
        .as_ref()
        .map(|result| {
            if result.error_samples.is_empty() {
                "No filesystem errors were recorded.".to_owned()
            } else {
                result
                    .error_samples
                    .iter()
                    .map(|error| format!("{}\n  {}", error.path, error.message))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
        })
        .unwrap_or_else(|| "No completed scan.".to_owned());
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Scan errors — Esc to close ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .padding(Padding::uniform(1)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
        .inner(Margin {
            horizontal: 0,
            vertical: 0,
        })
}
