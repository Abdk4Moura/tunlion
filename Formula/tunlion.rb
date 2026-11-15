# Homebrew formula for the tunlion CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Tunlion < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://tunlion.autumated.com"
  version "0.9.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.4/tunlion-aarch64-apple-darwin.tar.gz"
      sha256 "d312974843fb23f6d7308af10b2cfa6e240267d53aad41089a7406b09450733b"
    else
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.4/tunlion-x86_64-apple-darwin.tar.gz"
      sha256 "2b260f6ea3f9a8cf6e7821873335d442a0a2d48233d85b02a8e77a651f1952ef"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.4/tunlion-x86_64-unknown-linux-musl.tar.gz"
    sha256 "e53c14f8816250c792256ea1d4e9803a6ad9e4b3c58eb1ddd29a413ea1679669"
  end

  def install
    bin.install "tunlion"
    # `tl` is a convenience alias; it resolves to the canonical binary, so
    # `tl update` and `tl --version` behave exactly like `tunlion ...`.
    bin.install_symlink "tunlion" => "tl"
    generate_completions_from_executable(bin/"tunlion", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tunlion --version")
    assert_match version.to_s, shell_output("#{bin}/tl --version")
  end
end
