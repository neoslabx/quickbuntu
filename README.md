# QuickBuntu — Ubuntu Post-Installation Guide

**QuickBuntu** is a comprehensive post-installation setup for developers who use Ubuntu as their primary operating system.

It automates the configuration of a powerful, modern, and secure development environment — installing programming languages, IDEs, productivity tools, and system enhancements — all optimized to improve efficiency, performance, and daily workflow reliability.

Follow these steps in order to transform a fresh Ubuntu installation into a ready-to-code workstation.

* * *

## 1. Navigate to the Home Directory

Before executing any setup commands, it’s recommended to begin from your home directory. This ensures that files, logs, and configurations are stored consistently in user-specific paths rather than system-wide directories. Starting in `$HOME` guarantees that subsequent relative paths used throughout the guide resolve correctly, simplifying maintenance later.

```bash
cd $HOME
```

* * *

## 2. Disable Apport

First thing to do is check your `/var/crash` directory and see if there are any “crash” files. These are just normal text files and include details about a process. If you have a process crashing regularly, you most likely want to report it, so the vendor can implement a fix.

```bash
ls -la /var/crash
sudo rm -f /var/*.crash
sudo sed -i 's/^enabled=1/enabled=0/' /etc/default/apport
```

* * *

## 3. Update and Clean the System

A complete system update and cleanup is critical before installing new software. This process ensures you’re working with the latest security patches, kernel improvements, and dependency versions available in Ubuntu’s repositories. By cleaning and removing unused packages, you also free disk space and prevent version conflicts during the installation of future tools.

```bash
sudo apt -y update && sudo apt -y upgrade && sudo apt -y dist-upgrade
sudo apt -y remove && sudo apt -y autoremove
sudo apt -y clean && sudo apt -y autoclean
```

* * *

## 4. Remove Unused Default Applications (Thunderbird)

Many Ubuntu distributions include pre-installed applications that may not be necessary for developers. For example, **Thunderbird** is an email client that occupies space and system resources if unused. Removing such applications helps streamline the environment, reduces update time, and improves startup performance by avoiding unnecessary background services.

```bash
sudo snap list  
sudo snap remove --purge thunderbird
```

* * *

## 5. Install Essential System Libraries

These libraries provide the foundational components required to build, compile, and run modern software. Libraries like `libclang-dev`, `libssl-dev`, and `zlib1g-dev` are dependencies for compilers, encryption, and compression operations used in C/C++, Python, and Rust projects. Installing them early avoids compilation errors when setting up more advanced developer tools later.

```bash
sudo apt -y install libclang-dev libffi-dev libfuse2 libgl1 libssl-dev libudev-dev libxcb-cursor0 libxkbcommon-x11-0 zlib1g-dev
```

* * *

## 6. Install Developer Fonts

Readable fonts are essential for long coding sessions. Installing **DejaVu** and **Powerline** fonts ensures compatibility with customized terminal prompts, syntax-highlighted themes, and tools like `Oh My Zsh`. They enhance the visual clarity of code, improve readability of symbols, and make special Powerline icons display properly in terminals and IDEs.

```bash
sudo apt -y install fonts-dejavu fonts-powerline 
```

* * *

## 7. Install Core Developer Packages

This step equips your system with a wide range of developer utilities and productivity tools. From compilers (`build-essential`) to network analysis utilities (`nmap`, `wfuzz`, `nikto`), this set ensures your workstation can handle web development, cybersecurity tasks, and general system maintenance. Having them pre-installed means less downtime when switching between project types or debugging different environments.

```bash
sudo apt -y install apt-transport-https build-essential ca-certificates curl deborphan dirb dnsenum dpkg-deb easytag evolution evolution-ews exiftool \
filezilla flatpak gimp git golang gnome-tweaks hashcat httrack hydra inkscape john net-tools nikto nmap policykit-1 pkg-config protobuf-compiler \
secure-delete shutter software-properties-common sqlitebrowser sqlmap subversion testssl.sh trash-cli wapiti wfuzz wget whatweb whois zsh
```

* * *

## 8. Install Python and Related Packages

Python is essential for automation, data analysis, scripting, and backend web development. This step installs Python 3 along with scientific and web development libraries such as **NumPy**, **Flask**, **Pandas**, and **Matplotlib**. Symbolic links for `python` and `pip` are also added for command-line convenience, ensuring compatibility with older scripts expecting the `python` binary name.

```bash
sudo apt -y install python3 python3-bs4 python3-cryptography python3-dateutil python3-dev python3-django python3-flask python3-ipython \
python3-jinja2 python3-lxml python3-matplotlib python3-numpy python3-pandas python3-pip python3-pyqt5 python3-pyqt6 python3-requests \
python3-scipy python3-setuptools python3-sklearn python3-venv
sudo ln -s /usr/bin/python3 /usr/local/bin/python
sudo ln -s /usr/bin/pip3 /usr/local/bin/pip
```

* * *

## 9. Install Java Runtime and Development Kit

Java remains a foundational technology for enterprise, Android, and cross-platform applications. Installing both **JRE (Java Runtime Environment)** and **JDK (Java Development Kit)** provides the ability to compile and run Java programs. Many IDEs, including JetBrains products, rely on these components to function properly.

```bash
sudo apt -y install default-jdk default-jre
```

* * *

## 10. Install Docker and Docker Compose

Docker allows developers to create reproducible and isolated environments for applications. This installation enables containerized development, ensuring your code runs consistently across different systems. The included Docker Compose plugin simplifies orchestrating multi-container applications such as microservices or CI pipelines.

```bash
cd /tmp/
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt -y update && sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
cd $HOME
```

* * *

## 11. Install Sublime Text

**Sublime Text** is a lightweight yet powerful text editor favored for its speed and simplicity. It’s ideal for editing configuration files, scripts, or quick code snippets without the overhead of a full IDE. The repository method ensures automatic updates and integration with your system’s package manager.

```bash
cd /tmp/
wget -qO - "https://download.sublimetext.com/sublimehq-pub.gpg" | sudo tee /etc/apt/keyrings/sublimehq-pub.asc > /dev/null
echo -e 'Types: deb\nURIs: https://download.sublimetext.com/\nSuites: apt/stable/\nSigned-By: /etc/apt/keyrings/sublimehq-pub.asc' | sudo tee /etc/apt/sources.list.d/sublime-text.sources > /dev/null
sudo apt -y update && sudo apt -y install sublime-text
cd $HOME
```

* * *

## 12. Install Google Chrome

Installing Google Chrome gives you a reliable browser for web development and debugging. It supports modern web standards, developer tools, and extensions that simplify testing and profiling of websites or web applications. Having Chrome also ensures consistent behavior when testing projects destined for Chrome-based environments.

```bash
cd /tmp/
wget -O "google-chrome.deb" "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
sudo dpkg -i /tmp/google-chrome.deb
cd $HOME
```

* * *

## 13. Install Telegram Desktop

**Telegram Desktop** is useful for communication, file sharing, and automation via bots. For developers, it provides an efficient channel for collaborating on projects or receiving real-time notifications from CI/CD pipelines or monitoring bots. Installing it manually ensures you always get the latest official release without waiting for repository updates.

```bash
cd /tmp/
wget -O "telegram.tar.xz" "https://telegram.org/dl/desktop/linux"
tar -xf /tmp/telegram.tar.xz
mv /tmp/Telegram $HOME/.local/share/telegram
$HOME/.local/share/telegram/Telegram &> /dev/null &
cd $HOME
```

* * *

## 14. Install Tor Browser

**Tor Browser** enhances your online privacy by routing traffic through a secure, distributed network. It’s particularly useful for security researchers, ethical hackers, and developers who need to test websites under different anonymity conditions. This step installs the official Tor release and adds it as a desktop application for convenient launching.

```bash
cd /tmp/
wget -O "tor-browser-linux-x86_64-14.5.8.tar.xz" "https://www.torproject.org/dist/torbrowser/14.5.8/tor-browser-linux-x86_64-14.5.8.tar.xz"
tar -xf /tmp/tor-browser-linux-x86_64-14.5.8.tar.xz
mv /tmp/tor-browser $HOME/.local/share/tor-browser
cd $HOME/.local/share/tor-browser/
./start-tor-browser.desktop &> /dev/null &
sudo cp $HOME/.local/share/tor-browser/start-tor-browser.desktop /usr/share/applications/tor-browser.desktop
sudo chmod 644 /usr/share/applications/tor-browser.desktop
cd $HOME
```

* * *

## 15. Install Visual Studio Code

**VS Code** is a powerful, extensible IDE suitable for virtually any programming language. Its integrated Git support, extensions marketplace, and debugging capabilities make it a must-have for developers. Installing it directly from Microsoft’s servers guarantees compatibility with new features and faster updates than Ubuntu’s default repositories.

```bash
cd /tmp/
wget -O "visualcode.deb" "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64"
sudo dpkg -i /tmp/visualcode.deb
cd $HOME
```

* * *

## 16. Install KeePassXC

**KeePassXC** is an open-source password manager that securely stores credentials in encrypted databases. For developers managing multiple environments, servers, and API keys, it offers an offline alternative to cloud-based password tools. Its cross-platform compatibility and browser integration make it a reliable daily security companion.

```bash
cd /tmp/
sudo add-apt-repository -y ppa:phoerious/keepassxc
sudo apt -y update && sudo apt -y install keepassxc
cd $HOME
```

* * *

## 17. Install ProtonVPN

ProtonVPN encrypts your internet connection, hides your IP address, and protects sensitive development traffic. It’s especially useful when accessing public Wi-Fi, working remotely, or connecting to staging servers over insecure networks. This setup installs the official ProtonVPN client and verifies package integrity using SHA-256 checks.

```bash
cd /tmp/
wget -O "protonvpn-stable-release_1.0.8_all.deb" "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb"
sudo dpkg -i /tmp/protonvpn-stable-release_1.0.8_all.deb && sudo apt -y update
echo "0b14e71586b22e498eb20926c48c7b434b751149b1f2af9902ef1cfe6b03e180 protonvpn-stable-release_1.0.8_all.deb" | sha256sum --check -
sudo apt -y install proton-vpn-gnome-desktop
cd $HOME
```

* * *

## 18. Install ProtonMail Bridge

**ProtonMail Bridge** allows you to integrate ProtonMail with desktop clients like Thunderbird or Evolution. It creates a secure local encryption layer so your emails remain private while still accessible via standard IMAP/SMTP clients. This setup ensures encrypted email handling for developers working in privacy-sensitive environments.

```bash
cd /tmp/
wget -O "protonmail-bridge_3.21.2-1_amd64.deb" "https://proton.me/download/bridge/protonmail-bridge_3.21.2-1_amd64.deb"
sudo dpkg -i /tmp/protonmail-bridge_3.21.2-1_amd64.deb
cd $HOME
```

* * *

## 19. Install JetBrains Toolbox

JetBrains Toolbox simplifies managing IDEs like IntelliJ IDEA, PyCharm, WebStorm, and CLion. Instead of downloading each IDE separately, the Toolbox provides one interface to install, update, and configure all JetBrains products. This step requires manual download but significantly improves long-term maintainability for multi-language development workflows.

> **Manual step:** Download the Toolbox archive from the [official site](https://www.jetbrains.com/toolbox-app/download/download-thanks.html?platform=linux) and save it in `~/Downloads`.

```bash
sudo apt -y update
cd ~/Downloads
tar -xzf jetbrains-toolbox-*.tar.gz
mkdir -p $HOME/.local/share/JetBrains/Toolbox/
mv ~/Downloads/jetbrains-toolbox-*/bin $HOME/.local/share/JetBrains/Toolbox/
cd $HOME/.local/share/JetBrains/Toolbox/bin
./jetbrains-toolbox &> /dev/null &
cd $HOME
```

* * *

## 20. Install Rclone and Rclone Browser

**Rclone** is a command-line program that synchronizes files with over 40 cloud services, including Google Drive, Dropbox, and OneDrive. The **Rclone Browser** adds a graphical interface to simplify transfers and synchronization. Together, they offer developers an efficient way to back up code, synchronize configurations, or manage project data securely across devices.

```bash
cd /tmp/
wget -O "rclone.sh" "https://rclone.org/install.sh"
chmod +x /tmp/rclone.sh && sudo /tmp/rclone.sh
sudo apt -y install rclone-browser
cd $HOME
```

* * *

## 21. Clone Github Repositories

This step retrieves the Quickbuntu repositories from GitHub, which contains essential tools and scripts developed by NeosLab to automate and optimize Ubuntu setups.

```bash
cd /tmp/
git clone https://github.com/neoslabx/blitzclean
sudo dpkg -i /tmp/blitzclean/dist/blitzclean_*_all.deb
cd $HOME

cd /tmp/
git clone https://github.com/neoslabx/mediasane
sudo dpkg -i /tmp/mediasane/dist/mediasane_*_all.deb
cd $HOME
```

* * *

## 22. Customize the Terminal (Zsh, Powerlevel10k, and Plugins)

A developer’s terminal is a key productivity tool. This customization replaces the default Bash shell with **Zsh**, adds the **Oh My Zsh** framework, and enhances usability with features like autosuggestions and syntax highlighting. The **Powerlevel10k** theme adds a professional, informative prompt with Git, Python, and system status indicators. Together, these tweaks create a fast, elegant, and feature-rich command-line experience.

**Default User**

```bash
mkdir -p ~/.local/share/fonts
cd ~/.local/share/fonts
wget https://github.com/ryanoasis/nerd-fonts/releases/latest/download/Meslo.zip
unzip Meslo.zip
fc-cache -fv
rm -f Meslo.zip

cd /tmp
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
chsh -s $(which zsh)
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
wget https://github.com/ogham/exa/releases/latest/download/exa-linux-x86_64-v0.10.1.zip
unzip exa-linux-x86_64-v0.10.1.zip
sudo mv bin/exa /usr/local/bin/exa
sudo chmod +x /usr/local/bin/exa
echo -e "\n# Start ZSH\nif [ -t 1 ]; then\n  exec zsh\nfi" >> ~/.bashrc
mv ~/.zshrc ~/.zshrc.bak

cat <<'EOF' > ~/.zshrc
export ZSH="$HOME/.oh-my-zsh"
export ZSH_CUSTOM="$ZSH/custom"
ZSH_THEME="powerlevel10k/powerlevel10k"
plugins=(git zsh-syntax-highlighting zsh-autosuggestions)
alias ls='exa --icons'
alias ll='exa -l --icons'
alias la='exa -la --icons'
alias tree='tree -C'
source $ZSH/oh-my-zsh.sh
EOF

source ~/.zshrc
cd $HOME
```

**System User**

```bash
sudo -s
mkdir -p /root/.local/share/fonts
cd /root/.local/share/fonts
wget https://github.com/ryanoasis/nerd-fonts/releases/latest/download/Meslo.zip
unzip Meslo.zip
fc-cache -fv
rm -f Meslo.zip

cd /tmp
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-/root/.oh-my-zsh/custom}/themes/powerlevel10k
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-/root/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-/root/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

wget https://github.com/ogham/exa/releases/latest/download/exa-linux-x86_64-v0.10.1.zip
unzip exa-linux-x86_64-v0.10.1.zip
sudo mv bin/exa /usr/local/bin/exa
sudo chmod +x /usr/local/bin/exa
echo -e "\n# Start ZSH\nif [ -t 1 ]; then\n  exec zsh\nfi" >> /root/.bashrc
mv /root/.zshrc /root/.zshrc.bak

cat <<'EOF' > /root/.zshrc
export ZSH="/root/.oh-my-zsh"
export ZSH_CUSTOM="$ZSH/custom"
ZSH_THEME="powerlevel10k/powerlevel10k"
plugins=(git zsh-syntax-highlighting zsh-autosuggestions)
alias ls='exa --icons'
alias ll='exa -l --icons'
alias la='exa -la --icons'
alias tree='tree -C'
source $ZSH/oh-my-zsh.sh
EOF

source /root/.zshrc
cd /root/
```

* * *

## 23. Configure Powerlevel10k

After installation, configure the **Powerlevel10k** theme to match your preferences. The configuration wizard lets you adjust icons, color schemes, segment styles, and prompt behavior. Taking the time to fine-tune this step enhances readability and helps organize command-line information efficiently.

```bash
p10k configure
```

* * *

## 24. Final System Update and Cleanup

To conclude, perform another full system update and cleanup. This ensures that all installed packages are up to date, redundant files are removed, and the system is left in a stable and optimized state. Running this command post-setup keeps the environment lean, secure, and ready for immediate use.

```bash
sudo apt -y update && sudo apt -y upgrade && sudo apt -y dist-upgrade
sudo apt -y remove && sudo apt -y autoremove
sudo apt -y clean && sudo apt -y autoclean
```

* * *

## 25. Change SSH Port

Another thing that can be done on your machine is configuring the SSH service's listening port. It is set to port 22 by default, therefore if you are running a server, some hacking robots will target this port. Modifying this setting by using a different port is a simple measure to harden your server against automated attacks.

```bash
sudo sed -i 's/^#Port 22$/Port 49622/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

* * *

## Completion

**QuickBuntu setup complete!**

Your Ubuntu system is now transformed into a professional, developer-optimized workstation. You have full support for programming in multiple languages, secure communication tools, cloud synchronization, privacy protection, and a visually appealing terminal. From software development to cybersecurity analysis, this configuration ensures both flexibility and long-term stability for your daily workflow.

* * *

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

* * *

## Contact

For any issues, suggestions, or questions regarding the project, please open a new issue on the official GitHub repository or reach out directly to the maintainer through the [GitHub Issues](issues) page for further assistance and follow-up.