mod storage;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    
    // Set up callbacks and logic here
    let ui_weak = ui.as_weak();
    ui.on_save_password(move |title, username, _password| {
        if let Some(ui) = ui_weak.upgrade() {
            // TODO: Implement password saving logic using storage module
            // Note: Avoid logging sensitive information in production
            
            // For now, just show a success message
            ui.set_status_message(format!("Password saved for: {}", title).into());
        }
    });
    
    let ui_weak = ui.as_weak();
    ui.on_load_passwords(move || {
        if let Some(ui) = ui_weak.upgrade() {
            // TODO: Implement password loading logic using storage module
            
            ui.set_status_message("Passwords loaded!".into());
        }
    });
    
    ui.run()
}
