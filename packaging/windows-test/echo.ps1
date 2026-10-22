param([int]$Port = 45678)
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Host "echo server on 127.0.0.1:$Port"
try {
  while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $buffer = New-Object byte[] 65536
    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $stream.Write($buffer, 0, $read)
      $stream.Flush()
    }
    $client.Dispose()
  }
} finally { $listener.Stop() }
