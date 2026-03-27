use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Sparkline, Table};
use ratatui::Frame;
use tokio::sync::mpsc;

use crate::proxy::QueryMetrics;

/// A single DNS query event emitted by the proxy.
#[derive(Clone, Debug)]
pub struct QueryEvent {
    pub timestamp: Instant,
    pub domain: String,
    pub qtype: String,
    pub action: String,
    pub latency_ms: u64,
    pub proto: String,
}

/// Maximum number of events to keep in the ring buffer.
const MAX_EVENTS: usize = 200;

/// TUI refresh rate.
const TICK_RATE: Duration = Duration::from_millis(100);

/// Seconds of history for the sparkline.
const SPARKLINE_SECS: usize = 60;

pub struct App {
    events: VecDeque<QueryEvent>,
    metrics: std::sync::Arc<QueryMetrics>,
    rx: mpsc::Receiver<QueryEvent>,
    start_time: Instant,
    should_quit: bool,
    scroll_offset: usize,
    auto_scroll: bool,
    /// Per-second query counts for the sparkline (last 60 seconds).
    qps_history: VecDeque<u64>,
    /// Queries counted in the current second.
    qps_current: u64,
    /// When the current second bucket started.
    qps_tick: Instant,
}

impl App {
    pub fn new(metrics: std::sync::Arc<QueryMetrics>, rx: mpsc::Receiver<QueryEvent>) -> Self {
        let now = Instant::now();
        let mut qps_history = VecDeque::with_capacity(SPARKLINE_SECS);
        for _ in 0..SPARKLINE_SECS {
            qps_history.push_back(0);
        }
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS),
            metrics,
            rx,
            start_time: now,
            should_quit: false,
            scroll_offset: 0,
            auto_scroll: true,
            qps_history,
            qps_current: 0,
            qps_tick: now,
        }
    }

    fn push_event(&mut self, event: QueryEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Drain all pending query events from the channel (non-blocking).
    fn drain_events(&mut self) {
        let mut received = false;
        while let Ok(ev) = self.rx.try_recv() {
            self.push_event(ev);
            self.qps_current += 1;
            received = true;
        }
        if received && self.auto_scroll {
            self.scroll_offset = 0;
        }
        self.tick_sparkline();
    }

    /// Advance the sparkline buckets if a second has elapsed.
    fn tick_sparkline(&mut self) {
        let elapsed = self.qps_tick.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let missed_secs = elapsed.as_secs() as usize;
            // Push the current bucket
            self.qps_history.push_back(self.qps_current);
            // Fill any missed seconds with 0
            for _ in 1..missed_secs {
                self.qps_history.push_back(0);
            }
            // Trim to window size
            while self.qps_history.len() > SPARKLINE_SECS {
                self.qps_history.pop_front();
            }
            self.qps_current = 0;
            self.qps_tick = Instant::now();
        }
    }

    /// Run the TUI event loop. Blocks until the user presses 'q' or Ctrl-C.
    pub async fn run(mut self) -> anyhow::Result<()> {
        // Set up terminal
        terminal::enable_raw_mode()?;
        io::stdout().execute(EnterAlternateScreen)?;
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout()))?;

        let result = self.event_loop(&mut terminal).await;

        // Restore terminal
        terminal::disable_raw_mode()?;
        io::stdout().execute(LeaveAlternateScreen)?;

        result
    }

    async fn event_loop(
        &mut self,
        terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    ) -> anyhow::Result<()> {
        loop {
            if self.should_quit {
                return Ok(());
            }

            // Drain incoming query events
            self.drain_events();

            // Render
            terminal.draw(|frame| self.render(frame))?;

            // Poll for keyboard input (non-blocking with timeout)
            if event::poll(TICK_RATE)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                            KeyCode::Char('c')
                                if key
                                    .modifiers
                                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
                            {
                                self.should_quit = true;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if self.scroll_offset < self.events.len().saturating_sub(1) {
                                    self.scroll_offset += 1;
                                    self.auto_scroll = false;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if self.scroll_offset > 0 {
                                    self.scroll_offset -= 1;
                                } else {
                                    self.auto_scroll = true;
                                }
                            }
                            KeyCode::Home | KeyCode::Char('g') => {
                                self.scroll_offset = self.events.len().saturating_sub(1);
                                self.auto_scroll = false;
                            }
                            KeyCode::End | KeyCode::Char('G') => {
                                self.scroll_offset = 0;
                                self.auto_scroll = true;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn render(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4), // header / stats
                Constraint::Length(5), // sparkline
                Constraint::Min(8),    // live query stream
                Constraint::Length(9), // top blocked domains
            ])
            .split(frame.area());

        self.render_header(frame, chunks[0]);
        self.render_sparkline(frame, chunks[1]);
        self.render_stream(frame, chunks[2]);
        self.render_top_blocked(frame, chunks[3]);
    }

    fn render_header(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let snap = self.metrics.snapshot();
        let uptime = self.start_time.elapsed();
        let uptime_str = format_duration(uptime);

        let lines = vec![
            Line::from(vec![
                Span::styled(
                    " dnsink ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  press "),
                Span::styled("q", Style::default().fg(Color::Yellow)),
                Span::raw(" to quit"),
            ]),
            Line::from(vec![
                Span::raw(" Queries: "),
                Span::styled(
                    snap.total.to_string(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Blocked: "),
                Span::styled(
                    snap.blocked.to_string(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Allowed: "),
                Span::styled(
                    snap.allowed.to_string(),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  Avg: {:.1}ms", snap.avg_latency_ms())),
                Span::raw(format!("  Uptime: {uptime_str}")),
            ]),
        ];

        let block = Block::default().borders(Borders::ALL).title(" Stats ");
        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    }

    fn render_sparkline(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let data: Vec<u64> = self.qps_history.iter().copied().collect();
        let current_qps = self.qps_current;
        let peak = data.iter().copied().max().unwrap_or(0).max(current_qps);
        let title = format!(" Queries/sec (last 60s)  now: {current_qps}  peak: {peak} ");

        let sparkline = Sparkline::default()
            .block(Block::default().borders(Borders::ALL).title(title))
            .data(&data)
            .style(Style::default().fg(Color::Cyan));

        frame.render_widget(sparkline, area);
    }

    fn render_stream(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let header = Row::new(vec!["Time", "Action", "Domain", "Type", "Latency", "Proto"]).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        );

        let visible_rows = (area.height as usize).saturating_sub(3);
        let rows: Vec<Row> = self
            .events
            .iter()
            .rev()
            .skip(self.scroll_offset)
            .take(visible_rows)
            .map(|ev| {
                let elapsed = ev.timestamp.elapsed();
                let time_str = format!("{:.0}s ago", elapsed.as_secs_f64());
                let action_style = if ev.action == "blocked" {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green)
                };
                Row::new(vec![
                    Span::raw(time_str),
                    Span::styled(ev.action.to_uppercase(), action_style),
                    Span::raw(ev.domain.clone()),
                    Span::raw(ev.qtype.clone()),
                    Span::raw(format!("{}ms", ev.latency_ms)),
                    Span::raw(ev.proto.clone()),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(5),
        ];

        let scroll_indicator = if self.auto_scroll {
            " Live Query Stream (auto) "
        } else {
            " Live Query Stream (j/k scroll, G=latest) "
        };

        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .borders(Borders::ALL)
                .title(scroll_indicator),
        );

        frame.render_widget(table, area);
    }

    fn render_top_blocked(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let top = self.metrics.top_blocked(5);

        let rows: Vec<Row> = top
            .iter()
            .enumerate()
            .map(|(i, (domain, count))| {
                Row::new(vec![
                    Span::styled(format!(" {}.", i + 1), Style::default().fg(Color::Yellow)),
                    Span::styled(domain.clone(), Style::default().fg(Color::Red)),
                    Span::raw(count.to_string()),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(4),
            Constraint::Min(20),
            Constraint::Length(8),
        ];

        let table = Table::new(rows, widths).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Top Blocked Domains "),
        );

        frame.render_widget(table, area);
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}
