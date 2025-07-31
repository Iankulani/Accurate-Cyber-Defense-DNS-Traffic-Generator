use std::{
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    process,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};
use clap::{App, Arg};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use reqwest::blocking::Client;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    default_target: Option<String>,
    default_port: Option<u16>,
    traffic_duration: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            telegram_token: None,
            telegram_chat_id: None,
            default_target: None,
            default_port: Some(80),
            traffic_duration: Some(10),
        }
    }
}

struct AccurateCyberDefense {
    config: Config,
    running: Arc<AtomicBool>,
}

impl CyberSecurityTool {
    fn new() -> Self {
        let config = match fs::read_to_string("config.json") {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Config::default(),
        };

        CyberSecurityTool {
            config,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    fn save_config(&self) -> io::Result<()> {
        let config_str = serde_json::to_string_pretty(&self.config)?;
        fs::write("config.json", config_str)
    }

    fn ping(&self, ip: &str) -> io::Result<()> {
        let output = if cfg!(target_os = "windows") {
            process::Command::new("cmd")
                .args(&["/C", "ping", ip])
                .output()?
        } else {
            process::Command::new("ping")
                .arg("-c")
                .arg("4")
                .arg(ip)
                .output()?
        };

        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
        Ok(())
    }

    fn traceroute(&self, ip: &str) -> io::Result<()> {
        let output = if cfg!(target_os = "windows") {
            process::Command::new("tracert")
                .arg(ip)
                .output()?
        } else {
            process::Command::new("traceroute")
                .arg(ip)
                .output()?
        };

        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
        Ok(())
    }

    fn view_config(&self) {
        println!("Current Configuration:");
        println!("Telegram Token: {}", self.config.telegram_token.as_deref().unwrap_or("Not set"));
        println!("Telegram Chat ID: {}", self.config.telegram_chat_id.as_deref().unwrap_or("Not set"));
        println!("Default Target: {}", self.config.default_target.as_deref().unwrap_or("Not set"));
        println!("Default Port: {}", self.config.default_port.unwrap_or(0));
        println!("Traffic Duration (sec): {}", self.config.traffic_duration.unwrap_or(0));
    }

    fn config_telegram_token(&mut self, token: &str) {
        self.config.telegram_token = Some(token.to_string());
        if let Err(e) = self.save_config() {
            eprintln!("Failed to save config: {}", e);
        } else {
            println!("Telegram token updated and saved.");
        }
    }

    fn config_telegram_chat_id(&mut self, chat_id: &str) {
        self.config.telegram_chat_id = Some(chat_id.to_string());
        if let Err(e) = self.save_config() {
            eprintln!("Failed to save config: {}", e);
        } else {
            println!("Telegram chat ID updated and saved.");
        }
    }

    fn test_telegram(&self) -> io::Result<()> {
        let token = match &self.config.telegram_token {
            Some(t) => t,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Telegram token not configured")),
        };

        let chat_id = match &self.config.telegram_chat_id {
            Some(id) => id,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Telegram chat ID not configured")),
        };

        let client = Client::new();
        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        let params = HashMap::from([
            ("chat_id", chat_id.as_str()),
            ("text", "Test message from CyberSecurityTool"),
        ]);

        match client.post(&url).form(&params).send() {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Telegram test message sent successfully!");
                } else {
                    println!("Failed to send Telegram message. Status: {}", response.status());
                }
            }
            Err(e) => println!("Error sending Telegram message: {}", e),
        }

        Ok(())
    }

    fn generate_traffic(&self, target: &str, port: u16, duration_secs: u64) {
        let target_addr = match SocketAddr::from_str(&format!("{}:{}", target, port)) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("Invalid target address: {}", e);
                return;
            }
        };

        println!("Generating traffic to {}:{} for {} seconds...", target, port, duration_secs);
        
        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);
        
        let start_time = Instant::now();
        let duration = Duration::from_secs(duration_secs);
        
        let mut handles = vec![];
        
        // TCP traffic
        for _ in 0..10 {
            let running = Arc::clone(&running);
            let target_addr = target_addr.clone();
            handles.push(thread::spawn(move || {
                while running.load(Ordering::SeqCst) && start_time.elapsed() < duration {
                    match TcpStream::connect_timeout(&target_addr, Duration::from_millis(100)) {
                        Ok(_) => (),
                        Err(e) => eprintln!("TCP connection error: {}", e),
                    }
                }
            }));
        }
        
        // UDP traffic
        for _ in 0..10 {
            let running = Arc::clone(&running);
            let target_addr = target_addr.clone();
            handles.push(thread::spawn(move || {
                let socket = match UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Failed to create UDP socket: {}", e);
                        return;
                    }
                };
                
                let payload = [0u8; 1024]; // 1KB payload
                while running.load(Ordering::SeqCst) && start_time.elapsed() < duration {
                    match socket.send_to(&payload, &target_addr) {
                        Ok(_) => (),
                        Err(e) => eprintln!("UDP send error: {}", e),
                    }
                }
            }));
        }
        
        // Wait for duration or until interrupted
        while start_time.elapsed() < duration && running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }
        
        running.store(false, Ordering::SeqCst);
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        println!("Traffic generation completed.");
    }

    fn help(&self) {
        println!("Available commands:");
        println!("  help - Show this help message");
        println!("  ping <ip> - Ping an IP address");
        println!("  traceroute <ip> - Trace route to an IP address");
        println!("  view_config - View current configuration");
        println!("  config_telegram_token <token> - Set Telegram bot token");
        println!("  config_telegram_chat_id <id> - Set Telegram chat ID");
        println!("  test_telegram - Test Telegram notification");
        println!("  generate_traffic <ip> <port> <duration_secs> - Generate network traffic");
        println!("  clear - Clear the screen");
        println!("  exit - Exit the program");
    }

    fn clear_screen(&self) {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush().unwrap();
    }

    fn run(&mut self) {
        println!("Accurate Cyber Defense Security Terminal v1.0 - Type 'help' for commands");
        
        let running = Arc::clone(&self.running);
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
        
        loop {
            print!("> ");
            io::stdout().flush().unwrap();
            
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let input = input.trim();
            
            if input.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = input.split_whitespace().collect();
            match parts[0] {
                "help" => self.help(),
                "ping" => {
                    if parts.len() < 2 {
                        println!("Usage: ping <ip>");
                    } else {
                        if let Err(e) = self.ping(parts[1]) {
                            eprintln!("Error: {}", e);
                        }
                    }
                },
                "traceroute" => {
                    if parts.len() < 2 {
                        println!("Usage: traceroute <ip>");
                    } else {
                        if let Err(e) = self.traceroute(parts[1]) {
                            eprintln!("Error: {}", e);
                        }
                    }
                },
                "view_config" => self.view_config(),
                "config_telegram_token" => {
                    if parts.len() < 2 {
                        println!("Usage: config_telegram_token <token>");
                    } else {
                        self.config_telegram_token(parts[1]);
                    }
                },
                "config_telegram_chat_id" => {
                    if parts.len() < 2 {
                        println!("Usage: config_telegram_chat_id <id>");
                    } else {
                        self.config_telegram_chat_id(parts[1]);
                    }
                },
                "test_telegram" => {
                    if let Err(e) = self.test_telegram() {
                        eprintln!("Error: {}", e);
                    }
                },
                "generate_traffic" | "generate_traffic" => {
                    let target = if parts.len() > 1 {
                        parts[1].to_string()
                    } else {
                        self.config.default_target.clone().unwrap_or_else(|| {
                            println!("No target specified and no default target configured");
                            return "".to_string();
                        })
                    };
                    
                    if target.is_empty() {
                        continue;
                    }
                    
                    let port = if parts.len() > 2 {
                        match parts[2].parse() {
                            Ok(p) => p,
                            Err(_) => {
                                println!("Invalid port number");
                                continue;
                            }
                        }
                    } else {
                        self.config.default_port.unwrap_or(80)
                    };
                    
                    let duration = if parts.len() > 3 {
                        match parts[3].parse() {
                            Ok(d) => d,
                            Err(_) => {
                                println!("Invalid duration");
                                continue;
                            }
                        }
                    } else {
                        self.config.traffic_duration.unwrap_or(10)
                    };
                    
                    self.generate_traffic(&target, port, duration);
                },
                "clear" => self.clear_screen(),
                "exit" => break,
                _ => println!("Unknown command. Type 'help' for available commands."),
            }
        }
    }
}

fn main() {
    let matches = App::new("Accurate Cyber Defense Tool")
        .version("1.0")
        .author("Your Name")
        .about("Network monitoring and traffic generation tool")
        .arg(Arg::with_name("target")
            .short("t")
            .long("target")
            .value_name("IP")
            .help("Sets the target IP address")
            .takes_value(true))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("PORT")
            .help("Sets the target port")
            .takes_value(true))
        .arg(Arg::with_name("duration")
            .short("d")
            .long("duration")
            .value_name("SECONDS")
            .help("Sets the traffic generation duration in seconds")
            .takes_value(true))
        .arg(Arg::with_name("generate")
            .short("g")
            .long("generate")
            .help("Start generating traffic immediately"))
        .get_matches();

    let mut tool = AccurateCyberDefense::new();

    if matches.is_present("generate") {
        let target = matches.value_of("target")
            .map(|s| s.to_string())
            .or(tool.config.default_target.clone())
            .unwrap_or_else(|| {
                eprintln!("No target specified and no default target configured");
                process::exit(1);
            });

        let port = matches.value_of("port")
            .and_then(|s| s.parse().ok())
            .or(tool.config.default_port)
            .unwrap_or(80);

        let duration = matches.value_of("duration")
            .and_then(|s| s.parse().ok())
            .or(tool.config.traffic_duration)
            .unwrap_or(10);

        tool.generate_traffic(&target, port, duration);
    } else {
        tool.run();
    }
}