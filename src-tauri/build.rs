/*
  Nera VPN™
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  Nera VPN™ is a trademark of Vio Holdings LLC.
  This software is proprietary and confidential. Unauthorized copying,
  distribution, modification, or use of this software, via any medium,
  is strictly prohibited without written permission from the copyright holder.
  The source code and binaries are protected by copyright law and international treaties.
*/
fn main() {
    // #[cfg(windows)]
    // {
    //     embed_resource::compile("app.rc", embed_resource::NONE);
    // }
    
    tauri_build::build()
}
