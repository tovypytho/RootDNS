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

/**
 * Tiny root-side DNS53 bridge launched with app_process.
 *
 * It binds 127.0.0.1:53 as uid 0 and forwards DNS to the normal app process on
 * 127.0.0.1:5454. Keeping DoH in the unprivileged app process minimizes the
 * amount of code that runs as root.
 */
public final class RootPort53Forwarder {
    private final int targetPort;
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private volatile boolean running = true;
    private DatagramSocket udp;
    private ServerSocket tcp;

    private RootPort53Forwarder(int targetPort) {
        this.targetPort = targetPort;
    }

    public static void main(String[] args) throws Exception {
        int target = 5454;
        if (args != null && args.length > 0) {
            try { target = Integer.parseInt(args[0]); } catch (NumberFormatException ignored) {}
        }
        if (target < 1 || target > 65535) throw new IllegalArgumentException("bad target port");

        final RootPort53Forwarder bridge = new RootPort53Forwarder(target);
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override public void run() { bridge.stop(); }
        }, "td53-shutdown"));
        bridge.run();
    }

    private void run() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");

        udp = new DatagramSocket(null);
        udp.setReuseAddress(true);
        udp.bind(new InetSocketAddress(loopback, 53));

        tcp = new ServerSocket();
        tcp.setReuseAddress(true);
        tcp.bind(new InetSocketAddress(loopback, 53), 64);

        System.out.println("READY udp=127.0.0.1:53 tcp=127.0.0.1:53 target=127.0.0.1:" + targetPort);
        System.out.flush();

        Thread tcpThread = new Thread(new Runnable() {
            @Override public void run() { tcpLoop(); }
        }, "td53-tcp");
        tcpThread.setDaemon(true);
        tcpThread.start();

        udpLoop();
    }

    private void udpLoop() {
        while (running) {
            try {
                final byte[] buffer = new byte[65535];
                final DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
                udp.receive(incoming);
                final byte[] query = new byte[incoming.getLength()];
                System.arraycopy(incoming.getData(), incoming.getOffset(), query, 0, query.length);
                final InetAddress client = incoming.getAddress();
                final int clientPort = incoming.getPort();
                workers.execute(new Runnable() {
                    @Override public void run() { relayUdp(query, client, clientPort); }
                });
            } catch (SocketException e) {
                if (running) sleepBriefly();
            } catch (IOException e) {
                if (running) sleepBriefly();
            } catch (Throwable ignored) {
                if (running) sleepBriefly();
            }
        }
    }

    private void relayUdp(byte[] query, InetAddress client, int clientPort) {
        DatagramSocket upstream = null;
        try {
            upstream = new DatagramSocket();
            upstream.setSoTimeout(12000);
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            DatagramPacket request = new DatagramPacket(query, query.length, loopback, targetPort);
            upstream.send(request);

            byte[] buf = new byte[65535];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            upstream.receive(response);
            byte[] answer = new byte[response.getLength()];
            System.arraycopy(response.getData(), response.getOffset(), answer, 0, answer.length);

            DatagramSocket listener = udp;
            if (running && listener != null) {
                DatagramPacket reply = new DatagramPacket(answer, answer.length, client, clientPort);
                synchronized (listener) { listener.send(reply); }
            }
        } catch (Throwable ignored) {
        } finally {
            if (upstream != null) upstream.close();
        }
    }

    private void tcpLoop() {
        while (running) {
            try {
                final Socket client = tcp.accept();
                client.setSoTimeout(15000);
                workers.execute(new Runnable() {
                    @Override public void run() { relayTcp(client); }
                });
            } catch (SocketException e) {
                if (running) sleepBriefly();
            } catch (IOException e) {
                if (running) sleepBriefly();
            } catch (Throwable ignored) {
                if (running) sleepBriefly();
            }
        }
    }

    private void relayTcp(Socket client) {
        Socket upstream = null;
        try {
            upstream = new Socket();
            upstream.connect(new InetSocketAddress("127.0.0.1", targetPort), 5000);
            upstream.setSoTimeout(15000);

            DataInputStream ci = new DataInputStream(client.getInputStream());
            DataOutputStream co = new DataOutputStream(client.getOutputStream());
            DataInputStream ui = new DataInputStream(upstream.getInputStream());
            DataOutputStream uo = new DataOutputStream(upstream.getOutputStream());

            while (running) {
                int queryLength;
                try { queryLength = ci.readUnsignedShort(); }
                catch (EOFException eof) { break; }
                if (queryLength < 12 || queryLength > 65535) break;
                byte[] query = new byte[queryLength];
                ci.readFully(query);
                uo.writeShort(queryLength);
                uo.write(query);
                uo.flush();

                int answerLength = ui.readUnsignedShort();
                if (answerLength < 12 || answerLength > 65535) break;
                byte[] answer = new byte[answerLength];
                ui.readFully(answer);
                co.writeShort(answerLength);
                co.write(answer);
                co.flush();
            }
        } catch (Throwable ignored) {
        } finally {
            try { client.close(); } catch (IOException ignored) {}
            if (upstream != null) try { upstream.close(); } catch (IOException ignored) {}
        }
    }

    private void stop() {
        running = false;
        if (udp != null) udp.close();
        if (tcp != null) try { tcp.close(); } catch (IOException ignored) {}
        workers.shutdownNow();
    }

    private static void sleepBriefly() {
        try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
