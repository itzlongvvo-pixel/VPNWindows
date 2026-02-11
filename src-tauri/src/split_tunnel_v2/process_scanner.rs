//! Enumerates installed applications and running processes for the app picker.

use crate::split_tunnel_v2::types::*;
use std::collections::HashSet;
use std::path::PathBuf;
use sysinfo::System;
use tracing::info;

#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

pub struct ProcessScanner {
    system: std::sync::Mutex<System>,
}

impl ProcessScanner {
    pub fn new() -> Self {
        Self {
            system: std::sync::Mutex::new(System::new_all()),
        }
    }

    /// Get a list of all installed applications from the Windows registry
    #[cfg(windows)]
    pub fn get_installed_apps(&self) -> Result<Vec<InstalledApp>, SplitTunnelError> {
        let mut apps = Vec::new();
        let mut seen_paths = HashSet::new();

        let reg_paths = [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ];

        for (hkey, path) in &reg_paths {
            if let Ok(key) = RegKey::predef(*hkey).open_subkey(path) {
                for subkey_name in key.enum_keys().filter_map(Result::ok) {
                    if let Ok(subkey) = key.open_subkey(&subkey_name) {
                        let name: String = subkey.get_value("DisplayName").unwrap_or_default();
                        let install_loc: String = subkey.get_value("InstallLocation").unwrap_or_default();
                        let icon: String = subkey.get_value("DisplayIcon").unwrap_or_default();
                        let publisher: String = subkey.get_value("Publisher").unwrap_or_default();

                        if name.is_empty() || install_loc.is_empty() {
                            continue;
                        }

                        // Try to find the main .exe in the install location
                        if let Some(exe_path) = Self::find_main_exe(&install_loc) {
                            let path_str = exe_path.to_string_lossy().to_lowercase();
                            if seen_paths.contains(&path_str) {
                                continue;
                            }
                            seen_paths.insert(path_str);

                            apps.push(InstalledApp {
                                name,
                                exe_path: exe_path.to_string_lossy().to_string(),
                                icon_path: if icon.is_empty() { None } else { Some(icon) },
                                publisher: if publisher.is_empty() { None } else { Some(publisher) },
                            });
                        }
                    }
                }
            }
        }

        // Also scan common locations
        self.scan_common_locations(&mut apps, &mut seen_paths);

        apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        info!("Found {} installed applications", apps.len());
        Ok(apps)
    }

    /// Find the main executable in a directory
    fn find_main_exe(dir: &str) -> Option<PathBuf> {
        let dir_path = PathBuf::from(dir);
        if !dir_path.exists() {
            return None;
        }

        // Look for .exe files in the root
        if let Ok(entries) = std::fs::read_dir(&dir_path) {
            let exes: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .filter(|e| {
                    e.path().extension()
                        .map(|ext| ext == "exe")
                        .unwrap_or(false)
                })
                .map(|e| e.path())
                .collect();

            // Return the first exe, preferring ones that aren't "uninstall"
            exes.iter()
                .find(|p| {
                    let name = p.file_stem().unwrap_or_default().to_string_lossy().to_lowercase();
                    !name.contains("uninstall") && !name.contains("update")
                })
                .or_else(|| exes.first())
                .cloned()
        } else {
            None
        }
    }

    /// Scan common app directories
    fn scan_common_locations(
        &self,
        apps: &mut Vec<InstalledApp>,
        seen: &mut HashSet<String>,
    ) {
        let common_dirs = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ];

        for dir in &common_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(Result::ok) {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(exe) = Self::find_main_exe(&path.to_string_lossy()) {
                            let path_str = exe.to_string_lossy().to_lowercase();
                            if !seen.contains(&path_str) {
                                seen.insert(path_str);
                                apps.push(InstalledApp {
                                    name: path.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string(),
                                    exe_path: exe.to_string_lossy().to_string(),
                                    icon_path: None,
                                    publisher: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get all currently running processes
    pub fn get_running_processes(&self) -> Vec<(u32, String, PathBuf)> {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_processes();

        sys.processes()
            .iter()
            .filter_map(|(pid, proc)| {
                let exe = proc.exe()?;
                Some((pid.as_u32(), proc.name().to_string(), exe.to_path_buf()))
            })
            .collect()
    }

    /// Find PIDs for a given executable path
    pub fn find_pids_for_app(&self, exe_path: &PathBuf) -> Vec<u32> {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_processes();

        let target = exe_path.to_string_lossy().to_lowercase();

        sys.processes()
            .iter()
            .filter_map(|(pid, proc)| {
                let proc_exe = proc.exe()?.to_string_lossy().to_lowercase();
                if proc_exe == target {
                    Some(pid.as_u32())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(not(windows))]
impl ProcessScanner {
    pub fn get_installed_apps(&self) -> Result<Vec<InstalledApp>, SplitTunnelError> {
        Err(SplitTunnelError::ProcessError("Not supported on this platform".into()))
    }
}
