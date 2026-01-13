mod storage;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    
    // Set up callbacks and logic here
    let ui_weak = ui.as_weak();
    ui.on_save_password(move |title, username, _password| {
        let ui = ui_weak.unwrap();
        
        // TODO: Implement password saving logic using storage module
        println!("Saving password for: {} / {}", title, username);
        
        // For now, just show a success message
        ui.set_status_message("Password saved successfully!".into());
    });
    
    let ui_weak = ui.as_weak();
    ui.on_load_passwords(move || {
        let ui = ui_weak.unwrap();
        
        // TODO: Implement password loading logic using storage module
        println!("Loading passwords...");
        
        ui.set_status_message("Passwords loaded!".into());
    });
    
    ui.run()
}
