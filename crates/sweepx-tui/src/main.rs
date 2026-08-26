use std::env;
use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use sweepx_i18n::{Locale, detect_locale};
use sweepx_tui::{LoadLimits, NavigationAction, ReadOnlyAction, TuiState, ViewModel, render};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let input = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("usage: sweepx-tui <scan-output.json> [--locale zh-CN|en-US]");
            std::process::exit(2);
        }
    };

    let mut explicit_locale = None;
    while let Some(flag) = args.next() {
        if flag == "--locale"
            && let Some(value) = args.next()
        {
            explicit_locale = Some(value.parse::<Locale>()?);
        }
    }

    let locale = detect_locale(explicit_locale).locale();
    let view = ViewModel::from_path(&input, locale, 0, LoadLimits::default())?;
    run_tui(input, view)
}

fn run_tui(input: String, view: ViewModel) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_loop(&mut terminal, &input, view);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    input: &str,
    mut view: ViewModel,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = TuiState::default();

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            render(frame, area, &state, &view);
        })?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Tab => {
                    state =
                        state.reduce(ReadOnlyAction::Navigate(NavigationAction::NextPane), &view)
                }
                KeyCode::BackTab => {
                    state = state.reduce(
                        ReadOnlyAction::Navigate(NavigationAction::PreviousPane),
                        &view,
                    )
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    state = state.reduce(ReadOnlyAction::Navigate(NavigationAction::NextRow), &view)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    state = state.reduce(
                        ReadOnlyAction::Navigate(NavigationAction::PreviousRow),
                        &view,
                    )
                }
                KeyCode::PageDown => {
                    state =
                        state.reduce(ReadOnlyAction::Navigate(NavigationAction::NextPage), &view);
                }
                KeyCode::PageUp => {
                    state = state.reduce(
                        ReadOnlyAction::Navigate(NavigationAction::PreviousPage),
                        &view,
                    )
                }
                KeyCode::Esc => {
                    state = TuiState::default();
                }
                _ => {}
            }

            if view.needs_reload(state.cursor()) {
                view = ViewModel::from_path(
                    input,
                    view.locale(),
                    state.cursor().page_index,
                    view.limits(),
                )?
                .with_revision(view.revision());
                state = state.reduce(
                    ReadOnlyAction::Navigate(NavigationAction::RefreshRevision(view.revision())),
                    &view,
                );
            }
        }
    }

    Ok(())
}
