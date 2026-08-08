# Homebrew formula for the filament CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Filament < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://filament.autumated.com"
  version "0.8.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.3/filament-aarch64-apple-darwin.tar.gz"
      sha256 "80647b6a8b46b0ac0c43f8097348ede695700966aa9ad272cf7f2329226a4d7c"
    else
      url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.3/filament-x86_64-apple-darwin.tar.gz"
      sha256 "b6610bf2c432a99c72dbdd4f721e14580c0574f28486c0409227cdd15d17ef90"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/filament/releases/download/cli-v0.8.3/filament-x86_64-unknown-linux-musl.tar.gz"
    sha256 "85dbb510a6f0e559aee935060949afcc2ea5b87297b1f45ebe059cf42a4bf06f"
  end

  def install
    bin.install "filament"
    generate_completions_from_executable(bin/"filament", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/filament --version")
  end
end
