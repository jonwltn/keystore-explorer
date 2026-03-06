/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.kse;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.BiConsumer;

import javax.swing.SwingUtilities;

import org.kse.gui.KseFrame;
import org.kse.gui.preferences.PreferencesManager;

/**
 * A Singleton for managing the single instance infrastructure. The single
 * instance is managed using unix domain sockets/named pipes. The first instance
 * opens the socket/named pipe. Other instances of KSE will detect the existence
 * of the socket/pipe and notify the primary instance of the files to be opened.
 */
public enum SingleInstanceManager {

    /**
     * Singleton instance
     */
    INSTANCE;

    private static final String SOCKET_FILENAME = "kse-ipc.sock";

    private boolean isPrimary;
    private ServerSocketChannel serverChannel;
    private Thread listenerThread;

    /**
     * Attempt to become the primary instance of KSE if the feature is enabled.
     *
     * @return True if the instance is the primary instance. False, if not.
     */
    public boolean tryBecomePrimary() {
        if (!PreferencesManager.getPreferences().isSingleInstance()) {
            return true; // every instance is "primary"
        }

        Path socketPath = getSocketPath();

        try {
            serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(socketPath);
            serverChannel.bind(addr);
            isPrimary = true;
            return true; // is primary instance
        } catch (IOException e) {
            // Bind failed - another instance is running or file is stale
        }

        if (canConnectToPrimary(socketPath)) {
            return false; // primary instance exists
        }

        // Clean up stale socket file if needed
        try {
            Files.deleteIfExists(socketPath);
        } catch (IOException ignored) {
        }

        try {
            serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(socketPath);
            serverChannel.bind(addr);
            isPrimary = true;
            return true; // is primary after stale file cleanup
        } catch (IOException e) {
            // TODO JW - just open a second instance?
            // unknown state so return false
            return false;
        }

    }

    /**
     * Registers the main KseFrame with the single instance manager. Needed for opening files.
     *
     * @param kseFrame   The KseFrame.
     * @param fileOpener The file opener.
     */
    public void register(KseFrame kseFrame, BiConsumer<KseFrame, List<File>> fileOpener) {
        // Only start the listener thread if single instance is enabled and is primary.
        if (PreferencesManager.getPreferences().isSingleInstance() && !isPrimary) {
            return;
        }

        listenerThread = new Thread(() -> listenLoop(kseFrame, fileOpener), "kse-ipc-listener");
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    /**
     * Sends the files to open to the primary instance.
     *
     * @param files The list of files to send.
     * @throws IOException If an error occurred when sending the list of files.
     */
    public void sendToPrimary(List<File> files) throws IOException {
        if (files.isEmpty()) {
            return;
        }

        UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(getSocketPath());

        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(addr);
            writePaths(ch, files);
        }
    }

    private boolean canConnectToPrimary(Path socketPath) {
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(socketPath);
            ch.connect(addr);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void listenLoop(KseFrame kseFrame, BiConsumer<KseFrame, List<File>> fileOpener) {
        try {
            while (true) {
                SocketChannel client = serverChannel.accept();
                handleRequest(client, kseFrame, fileOpener);
            }
        } catch (IOException e) {
            // TODO JW - log and exit thread
        }
    }

    private void handleRequest(SocketChannel client, KseFrame kseFrame, BiConsumer<KseFrame, List<File>> fileOpener) {
        try (client) {
            List<File> paths = readPaths(client);
            if (!paths.isEmpty()) {
                SwingUtilities.invokeLater(() -> fileOpener.accept(kseFrame, paths));
            }
        } catch (IOException e) {
            // TODO JW - log
        }
    }

    private void writePaths(WritableByteChannel ch, List<File> files) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);

        oos.writeObject(files.toArray(File[]::new));
        oos.flush();

        ByteBuffer buf = ByteBuffer.wrap(baos.toByteArray());
        while (buf.hasRemaining()) {
            ch.write(buf);
        }
    }

    private List<File> readPaths(ReadableByteChannel ch) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(Channels.newInputStream(ch))) {
            Object incomingObject = ois.readObject();
            if (incomingObject instanceof File[]) {
                return Arrays.asList((File[]) incomingObject);
            }
        } catch (ClassNotFoundException e) {
            // Ignore. File[] is always be available.
        }
        return Collections.EMPTY_LIST;
    }

    private Path getSocketPath() {
        return Path.of(System.getProperty("java.io.tmpdir"), SOCKET_FILENAME);
    }

    /**
     * Closes the socket and cleans up.
     */
    public void shutdown() {
        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close();
            }
        } catch (IOException ignored) {
        }

        try {
            Files.deleteIfExists(getSocketPath());
        } catch (IOException ignored) {
        }
    }
}
