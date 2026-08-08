# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.8.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.4/filament-aarch64-apple-darwin.tar.gz"
      sha256 "0dc847790c7efafea4abdc811d09b5bbedb791a5c3a99f55cfcb279b1fef8440"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.4/filament-x86_64-apple-darwin.tar.gz"
      sha256 "36709411de662275023055f91a9395c546c6a1387bb8031826bc3509508b57d9"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.4/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "d4596edf391fa8e02489015723eed974b061600ff64cee1ea7b6a5828331d10d"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
