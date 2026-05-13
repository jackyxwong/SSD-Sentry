class SsdSentry < Formula
  desc "SSD Sentry: macOS SSD write protection daemon for runaway disk writers"
  homepage "https://github.com/jackyxwong/SSD-Sentry"
  url "https://github.com/jackyxwong/SSD-Sentry/releases/download/v1.0.0/ssd-sentry-v1.0.0.tar.gz"
  sha256 "67f2a6274c9c043b2d3281951dae8385154c86df28ebdbfb7309c50365ad21a7"
  license "Apache-2.0"

  depends_on "python@3.11"

  def install
    libexec.install "ssd_sentry_monitor.py",
                    "config.json",
                    "ssd-sentry",
                    "ssd-sentry-setup.sh",
                    "ssd-sentry-uninstall.sh",
                    "com.ssdsentry.daemon.plist",
                    "ssd-sentry-dry-run.sh",
                    "README.md",
                    "requirements.txt",
                    "LICENSE",
                    "NOTICE"

    (libexec/"ssd_sentry_monitor.py").chmod 0755
    (libexec/"ssd-sentry").chmod 0755
    (libexec/"ssd-sentry-setup.sh").chmod 0755
    (libexec/"ssd-sentry-uninstall.sh").chmod 0755
    (libexec/"ssd-sentry-dry-run.sh").chmod 0755

    bin.install_symlink libexec/"ssd-sentry" => "ssd-sentry"
    bin.install_symlink libexec/"ssd-sentry-setup.sh" => "ssd-sentry-setup"
    bin.install_symlink libexec/"ssd-sentry-uninstall.sh" => "ssd-sentry-uninstall"
  end

  def caveats
    <<~EOS
      To install the system daemon (requires sudo):
        sudo "$(brew --prefix)/bin/ssd-sentry-setup"

      To manage the daemon after installation:
        ssd-sentry status
        ssd-sentry status --watch
        ssd-sentry logs
        sudo "$(brew --prefix)/bin/ssd-sentry" reload
        sudo "$(brew --prefix)/bin/ssd-sentry" restart
        ssd-sentry dry-run

      To uninstall:
        sudo "$(brew --prefix)/bin/ssd-sentry-uninstall"

      If you installed via Homebrew, run the uninstall command above before:
        brew uninstall ssd-sentry
    EOS
  end

  test do
    system "#{libexec}/ssd_sentry_monitor.py", "--version"
  end
end
