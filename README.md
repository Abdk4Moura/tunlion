# Quickshare

Quickshare is a free web app that allows file sharing through a Peer-to-Peer(P2P) network.
It uses a middleman or signalling channel using firebase connection and then establishes a direct connection between the peers.
The files are transferred directly between the peers and the middleman is not involved in the transfer. The middleman/signalling channel is only used to establish a connection between the peers.

## Features

1. Share files with anyone in the world.
2. No size limit on files.
3. No need to install any software.
4. No need to sign up.
5. No need to login.
6. QR code for easy sharing.
7. Share files with multiple people at once.

## How to use

1. Go to [Quickshare](https://quickshare-1.web.app/).
2. Click on the `+` symbol to generate a QR code for sharing as well as a link.
3. Share the QR code or the link with the person you want to share with.
4. After connection is established, you can drag and drop files to share.
5. Alternatively, you can click on the avatar of theh user to select files to share.
6. You can also share files with multiple people at once by clicking on the `+` symbol again and sharing the new QR code or link.

## Credits

This is inspired by Sharedrop <link for sharedrop> and uses WebRTC for peer-to-peer connection and Firebase for the signalling channel.

(PS: You can also share files with yourself by opening the link in a new tab.)
