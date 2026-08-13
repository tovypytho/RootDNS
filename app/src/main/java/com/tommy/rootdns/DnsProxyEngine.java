package com.tommy.rootdns;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class DnsProxyEngine {
    private final Object lock = new Object();
    private volatile boolean running;
    private DatagramSocket udpSocket;
    private ServerSocket tcpSocket;
    private ExecutorService workers;
    private Thread udpThread;
    private Thread tcpThread;
    private DohClient doh;

    void start(String endpoint, int port) throws IOException {
        synchronized (lock) {
            stopLocked();
            doh = new DohClient(endpoint);
            workers = Executors.newFixedThreadPool(8);

            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            udpSocket = new DatagramSocket(null);
            udpSocket.setReuseAddress(true);
            udpSocket.bind(new InetSocketAddress(loopback, port));

            tcpSocket = new ServerSocket();
            tcpSocket.setReuseAddress(true);
            tcpSocket.bind(new InetSocketAddress(loopback, port), 64);

            running = true;
            udpThread = new Thread(new Runnable() {
                @Override public void run() { udpLoop(); }
            }, "td-u");
            tcpThread = new Thread(new Runnable() {
                @Override public void run() { tcpLoop(); }
            }, "td-t");
            udpThread.start();
            tcpThread.start();
        }
    }

    boolean isRunning() {
        return running;
    }

    boolean healthCheck() {
        DohClient client = doh;
        if (!running || client == null) return false;
        try {
            byte[] response = client.query(DnsPackets.aQuery("example.com"));
            return response.length >= 12 && (response[2] & 0x80) != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    void stop() {
        synchronized (lock) {
            stopLocked();
        }
    }

    private void stopLocked() {
        running = false;
        if (udpSocket != null) {
            udpSocket.close();
            udpSocket = null;
        }
        if (tcpSocket != null) {
            try { tcpSocket.close(); } catch (IOException ignored) {}
            tcpSocket = null;
        }
        if (workers != null) {
            workers.shutdownNow();
            workers = null;
        }
        doh = null;
    }

    private void udpLoop() {
        while (running) {
            try {
                final byte[] buffer = new byte[65535];
                final DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                udpSocket.receive(packet);
                final byte[] request = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), request, 0, packet.getLength());
                final InetAddress address = packet.getAddress();
                final int sourcePort = packet.getPort();
                ExecutorService pool = workers;
                if (pool != null) {
                    pool.execute(new Runnable() {
                        @Override public void run() { forwardUdp(request, address, sourcePort); }
                    });
                }
            } catch (SocketException e) {
                if (running) sleepBriefly();
            } catch (IOException e) {
                if (running) sleepBriefly();
            }
        }
    }

    private void forwardUdp(byte[] request, InetAddress address, int sourcePort) {
        try {
            DohClient client = doh;
            DatagramSocket socket = udpSocket;
            if (!running || client == null || socket == null) return;
            byte[] response = client.query(request);
            DatagramPacket reply = new DatagramPacket(response, response.length, address, sourcePort);
            synchronized (socket) {
                socket.send(reply);
            }
        } catch (Throwable ignored) {
            // Client will retry; the service watchdog handles persistent upstream failure.
        }
    }

    private void tcpLoop() {
        while (running) {
            try {
                final Socket socket = tcpSocket.accept();
                socket.setSoTimeout(15000);
                ExecutorService pool = workers;
                if (pool != null) {
                    pool.execute(new Runnable() {
                        @Override public void run() { handleTcp(socket); }
                    });
                } else {
                    socket.close();
                }
            } catch (SocketException e) {
                if (running) sleepBriefly();
            } catch (IOException e) {
                if (running) sleepBriefly();
            }
        }
    }

    private void handleTcp(Socket socket) {
        try {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            while (running) {
                int length;
                try {
                    length = in.readUnsignedShort();
                } catch (EOFException eof) {
                    break;
                }
                if (length < 12 || length > 65535) break;
                byte[] request = new byte[length];
                in.readFully(request);
                DohClient client = doh;
                if (client == null) break;
                byte[] response = client.query(request);
                out.writeShort(response.length);
                out.write(response);
                out.flush();
            }
        } catch (Throwable ignored) {
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private static void sleepBriefly() {
        try { Thread.sleep(100); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
    }
}
