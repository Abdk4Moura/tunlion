# Homebrew formula for the tunlion CLI — lives in Abdk4Moura/homebrew-tap.
# Regenerated per release by packaging/release-followup.sh.
class Tunlion < Formula
  desc "P2P file transfer between terminals and browsers - no upload, no account"
  homepage "https://tunlion.autumated.com"
  version "0.9.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.2/tunlion-aarch64-apple-darwin.tar.gz"
      sha256 "f82fe897c1c3bb1d244ffe9895d4a09c3603ac0f6a2c520ecf2241693f1d4567"
    else
      url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.2/tunlion-x86_64-apple-darwin.tar.gz"
      sha256 "2c2181b445f13f594ffb80f4e00fa666703978e16e95a68f9e6a7fbdd4743139"
    end
  end

  on_linux do
    url "https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.2/tunlion-x86_64-unknown-linux-musl.tar.gz"
    sha256 "adaaa26f89fe429fb943ec29a982327e304bfe15be93b69659db2f92825731bc"
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
