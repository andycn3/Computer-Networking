package ca.ubc.cs317.dict.net;

import ca.ubc.cs317.dict.model.Database;
import ca.ubc.cs317.dict.model.Definition;
import ca.ubc.cs317.dict.model.MatchingStrategy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;


import java.util.*;

/**
 * Created by Jonatan on 2017-09-09.
 */
public class DictionaryConnection {

    private static final int DEFAULT_PORT = 2628;

    /** Establishes a new connection with a DICT server using an explicit host and port number, and handles initial
     * welcome messages.
     *
     * @param host Name of the host where the DICT server is running
     * @param port Port number used by the DICT server
     * @throws DictConnectionException If the host does not exist, the connection can't be established, or the messages
     * don't match their expected value.
     */
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    public DictionaryConnection(String host, int port) throws DictConnectionException {
        try {
            socket = new Socket(host, port);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

            Status welcome = Status.readStatus(in);
            if (welcome.getStatusCode() != 220) {
                throw new DictConnectionException("Expected 220 welcome, got " +
                        welcome.getStatusCode() + " " + welcome.getDetails());
            }

        } catch (IOException e) {
            throw new DictConnectionException("Could not connect to " + host + ":" + port, e);
        }
    }

    /** Establishes a new connection with a DICT server using an explicit host, with the default DICT port number, and
     * handles initial welcome messages.
     *
     * @param host Name of the host where the DICT server is running
     * @throws DictConnectionException If the host does not exist, the connection can't be established, or the messages
     * don't match their expected value.
     */
    public DictionaryConnection(String host) throws DictConnectionException {
        this(host, DEFAULT_PORT);
    }

    /** Sends the final QUIT message and closes the connection with the server. This function ignores any exception that
     * may happen while sending the message, receiving its reply, or closing the connection.
     *
     */
    public synchronized void close() {
        try {
            if (out != null) {
                out.println("QUIT");
                if (in != null) {
                    try { Status.readStatus(in); } catch (DictConnectionException ignored) {}
                }
            }
        } catch (Exception ignored) {
        } finally {
            try { if (in != null) in.close(); } catch (IOException ignored) {}
            try { if (out != null) out.close(); } catch (Exception ignored) {}
            try { if (socket != null) socket.close(); } catch (IOException ignored) {}
            in = null; out = null; socket = null;
        }
    }

    /** Requests and retrieves all definitions for a specific word.
     *
     * @param word The word whose definition is to be retrieved.
     * @param database The database to be used to retrieve the definition. A special database may be specified,
     *                 indicating either that all regular databases should be used (database name '*'), or that only
     *                 definitions in the first database that has a definition for the word should be used
     *                 (database '!').
     * @return A collection of Definition objects containing all definitions returned by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Collection<Definition> getDefinitions(String word, Database database) throws DictConnectionException {
        Collection<Definition> set = new ArrayList<>();

        String dbName = (database == null) ? "*" : database.getName();
        out.println("DEFINE " + dbName + " " + atom(word));

        Status st = Status.readStatus(in);

        if (st.getStatusCode() == 552) {
            return set;
        }

        if (st.getStatusCode() == 550) {
            return set;
        }

        if (st.getStatusCode() == 150) {
            st = Status.readStatus(in);
        } else if (st.getStatusCode() == 151) {
        } else {
            throw new DictConnectionException("Unexpected response to DEFINE: " + st.getStatusCode());
        }

        while (st.getStatusCode() == 151) {

            String[] atoms = DictStringParser.splitAtoms(st.getDetails());
            if (atoms.length < 2) {
                throw new DictConnectionException("Malformed 151 reply: " + st.getDetails());
            }

            String defWord = atoms[0];
            String defDb = atoms[1];

            Definition d = new Definition(defWord, defDb);

            StringBuilder sb = new StringBuilder();
            String line;
            try {
                while ((line = in.readLine()) != null) {
                    if (line.equals(".")) break;
                    sb.append(line).append("\n");
                }
            } catch (IOException e) {
                throw new DictConnectionException("Error reading definition text", e);
            }

            d.setDefinition(sb.toString());
            set.add(d);

            st = Status.readStatus(in);
        }

        if (st.getStatusCode() != 250) {
            throw new DictConnectionException("DEFINE did not complete correctly.");
        }

        return set;
    }

    /** Requests and retrieves a list of matches for a specific word pattern.
     *
     * @param word     The word whose definition is to be retrieved.
     * @param strategy The strategy to be used to retrieve the list of matches (e.g., prefix, exact).
     * @param database The database to be used to retrieve the definition. A special database may be specified,
     *                 indicating either that all regular databases should be used (database name '*'), or that only
     *                 matches in the first database that has a match for the word should be used (database '!').
     * @return A set of word matches returned by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Set<String> getMatchList(String word, MatchingStrategy strategy, Database database) throws DictConnectionException {
        Set<String> set = new LinkedHashSet<>();

        String dbName = (database == null) ? "*" : database.getName();
        String stratName = (strategy == null) ? "prefix" : strategy.getName();

        out.println("MATCH " + dbName + " " + stratName + " " + atom(word));

        Status st = Status.readStatus(in);

        if (st.getStatusCode() == 552) {
            return set;
        }
        if (st.getStatusCode() == 550 || st.getStatusCode() == 551) {
            return set;
        }

        if (st.getStatusCode() != 152) {
            throw new DictConnectionException("Unexpected response to MATCH: " + st.getStatusCode());
        }

        String line;
        try {
            while ((line = in.readLine()) != null) {
                if (line.equals(".")) break;
                String[] atoms = DictStringParser.splitAtoms(line);
                if (atoms.length >= 2) {
                    set.add(atoms[1]);
                } else if (atoms.length == 1) {
                    set.add(atoms[0]);
                }
            }
        } catch (IOException e) {
            throw new DictConnectionException("Error reading matches", e);
        }

        Status done = Status.readStatus(in);
        if (done.getStatusCode() != 250) {
            throw new DictConnectionException("MATCH did not complete correctly.");
        }

        return set;
    }

    /** Requests and retrieves a map of database name to an equivalent database object for all valid databases used in the server.
     *
     * @return A map of Database objects supported by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Map<String, Database> getDatabaseList() throws DictConnectionException {
        Map<String, Database> databaseMap = new HashMap<>();

        out.println("SHOW DB");

        Status st = Status.readStatus(in);

        if (st.getStatusCode() == 554) {
            return databaseMap;
        }

        if (st.getStatusCode() != 110) {
            if (st.isNegativeReply()) {
                throw new DictConnectionException("SHOW DB failed: " + st.getDetails());
            }
            throw new DictConnectionException("Unexpected status from SHOW DB: " + st.getStatusCode());
        }

        String line;
        try {
            while ((line = in.readLine()) != null) {
                if (line.equals(".")) break;

                String[] atoms = DictStringParser.splitAtoms(line);
                if (atoms.length >= 2) {
                    databaseMap.put(atoms[0], new Database(atoms[0], atoms[1]));
                }
            }
        } catch (IOException e) {
            throw new DictConnectionException("Error reading database list.", e);
        }

        Status done = Status.readStatus(in);
        if (done.getStatusCode() != 250) {
            throw new DictConnectionException("SHOW DB did not complete correctly.");
        }

        return databaseMap;
    }

    /** Requests and retrieves a list of all valid matching strategies supported by the server.
     *
     * @return A set of MatchingStrategy objects supported by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Set<MatchingStrategy> getStrategyList() throws DictConnectionException {
        Set<MatchingStrategy> set = new LinkedHashSet<>();
        out.println("SHOW STRAT");

        Status st = Status.readStatus(in);

        if (st.getStatusCode() == 555) {
            return set;
        }

        if (st.getStatusCode() != 111) {
            if (st.isNegativeReply()) {
                throw new DictConnectionException("SHOW STRAT failed: " + st.getDetails());
            }
            throw new DictConnectionException("Unexpected status from SHOW STRAT: " + st.getStatusCode());
        }

        String line;
        try {
            while ((line = in.readLine()) != null) {
                if (line.equals(".")) break;

                String[] atoms = DictStringParser.splitAtoms(line);
                if (atoms.length >= 2) {
                    set.add(new MatchingStrategy(atoms[0], atoms[1]));
                }
            }
        } catch (IOException e) {
            throw new DictConnectionException("Error reading strategy list.", e);
        }

        Status done = Status.readStatus(in);
        if (done.getStatusCode() != 250) {
            throw new DictConnectionException("SHOW STRAT did not complete correctly.");
        }

        return set;
    }

    /** Requests and retrieves detailed information about the currently selected database.
     *
     * @return A string containing the information returned by the server in response to a "SHOW INFO <db>" command.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized String getDatabaseInfo(Database d) throws DictConnectionException {
        StringBuilder sb = new StringBuilder();

        String dbName = (d == null) ? "*" : d.getName();
        out.println("SHOW INFO " + dbName);

        Status st = Status.readStatus(in);

        if (st.getStatusCode() != 112) {
            if (st.isNegativeReply()) {
                throw new DictConnectionException("SHOW INFO failed: " + st.getDetails());
            }
            throw new DictConnectionException("Unexpected status from SHOW INFO: " + st.getStatusCode());
        }

        String line;
        try {
            while ((line = in.readLine()) != null) {
                if (line.equals(".")) break;
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            throw new DictConnectionException("Error reading database info.", e);
        }

        Status done = Status.readStatus(in);
        if (done.getStatusCode() != 250) {
            throw new DictConnectionException("SHOW INFO did not complete correctly.");
        }

        return sb.toString();
    }

    private String atom(String s) {
        if (s == null) return "\"\"";
        if (s.isEmpty() || s.matches(".*\\s+.*")) {
            return "\"" + s.replace("\"", "") + "\"";
        }
        return s;
    }
}
