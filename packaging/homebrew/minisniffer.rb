# Homebrew formula for MiniSniffer, kept in-tree under packaging/homebrew/
# for future tap use rather than published to homebrew-core.
#
# Local install without a tap:
#   brew install --build-from-source ./packaging/homebrew/minisniffer.rb
#
# Once tapped (e.g. `brew tap <owner>/<tap>`), users would run
# `brew install <owner>/<tap>/minisniffer` instead.
#
# The stable `url`/`sha256` below must be filled in after the first tagged
# release is published (see .github/workflows/release.yml, which generates
# a source tarball and its SHA256 checksum). Until then, `brew install --HEAD
# ./packaging/homebrew/minisniffer.rb` builds directly from this repository's
# default branch.
class Minisniffer < Formula
  desc "Small C packet sniffer and network analyzer built on libpcap"
  homepage "https://github.com/finn-abel/PacketScope"
  license "MIT"

  # Fill in after cutting the first release, e.g.:
  #   url "https://github.com/finn-abel/PacketScope/archive/refs/tags/v0.2.0.tar.gz"
  #   sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_SHA256SUMS"
  url "https://github.com/finn-abel/PacketScope/archive/refs/tags/v0.0.0.tar.gz"
  sha256 ""

  head "https://github.com/finn-abel/PacketScope.git", branch: "main"

  depends_on "pkg-config" => :build
  depends_on "libpcap"

  def install
    system "make", "CC=#{ENV.cc}"
    bin.install "MiniSniffer"
    man1.install "man/minisniffer.1"
    bash_completion.install "completions/minisniffer.bash" => "minisniffer"
    zsh_completion.install "completions/_minisniffer"
    fish_completion.install "completions/minisniffer.fish"
  end

  test do
    assert_match "MiniSniffer #{version}", shell_output("#{bin}/MiniSniffer --version")
    assert_match "Usage: #{bin}/MiniSniffer", shell_output("#{bin}/MiniSniffer --help")
  end
end
