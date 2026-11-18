package org.telegram.utils.proxy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;

// Checks of PlumaPathPolicy (A-129, PATH_POLICY_JAVA of ci/patch.py) on a JVM; ci/patch_test.py
// compiles and runs it (PathSelectionTest).
public final class PlumaPathPolicyTest {
    private static int checks;

    public static void main(String[] args) throws Exception {
        probeBytes();
        obfuscation();
        reader();
        measure();
        params();
        decisions();
        memory();
        networkKey();
        System.out.println("PlumaPathPolicyTest: " + checks + " checks passed");
    }

    private static void check(boolean condition, String what) {
        checks++;
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    private static String hex(byte[] bytes, int from, int to) {
        StringBuilder out = new StringBuilder();
        for (int i = from; i < to; i++) {
            out.append(String.format("%02x", bytes[i] & 0xff));
        }
        return out.toString();
    }

    private static byte[] seq16() {
        byte[] nonce = new byte[16];
        for (int i = 0; i < 16; i++) {
            nonce[i] = (byte) i;
        }
        return nonce;
    }

    // The test vectors of the gateway's contract (brief 113, "Контракт пробы").
    private static void probeBytes() {
        byte[] m = PlumaPathPolicy.probe(0, seq16(), 65536, new byte[0]);
        byte[] data = Arrays.copyOfRange(m, 20, m.length);
        check(data.length == 28, "empty pad: 28 bytes of message data");
        check(hex(data, 0, 28).equals("306d315c000102030405060708090a0b0c0d0e0f0000010000000000"), "empty pad vector");
        check(ByteBuffer.wrap(m, 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() == 28, "message_data_length 28");
        check(hex(m, 0, 8).equals("0000000000000000"), "auth_key_id 0");
        byte[] big = PlumaPathPolicy.probe(0, seq16(), 65536, new byte[20480]);
        check(ByteBuffer.wrap(big, 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() == 20508, "20 KiB pad: 24 + 4 + 20480");
        check(hex(big, 20 + 24, 20 + 28).equals("fe005000"), "20 KiB pad: fe 00 50 00");
        check(big.length == 20 + 20508, "20 KiB pad: no extra bytes");
        byte[] req = PlumaPathPolicy.reqPqMulti(0, seq16());
        check(req.length == 40 && hex(req, 20, 24).equals("f18e7ebe"), "req_pq_multi");
        check(PlumaPathPolicy.tlBytes(new byte[253]).length == 256 && PlumaPathPolicy.tlBytes(new byte[253])[0] == (byte) 253, "tl bytes 253");
        check(PlumaPathPolicy.tlBytes(new byte[254]).length == 260 && PlumaPathPolicy.tlBytes(new byte[254])[0] == (byte) 0xfe, "tl bytes 254");
        check(PlumaPathPolicy.tlBytesLength(16384) == 16388 && PlumaPathPolicy.tlBytesLength(0) == 4, "tl bytes length");
        check(hex(PlumaPathPolicy.frame(new byte[8]), 0, 4).equals("08000000"), "intermediate frame");
        check(PlumaPathPolicy.chunks(65536) == 4 && PlumaPathPolicy.chunks(196608) == 12, "chunks");
        check(PlumaPathPolicy.chunks(1) == 1 && PlumaPathPolicy.chunks(1 << 30) == 32 && PlumaPathPolicy.chunks(20000) == 2, "chunks of clamped down");
        long id = PlumaPathPolicy.msgId(1_700_000_000_500L);
        check(id >>> 32 == 1_700_000_000L && (id & 3) == 0 && (id & 0xffffffffL) == 2147483648L, "msg_id");
    }

    // A gateway's view of the header: decrypt with bytes 8-55, encrypt with them reversed.
    private static void obfuscation() throws Exception {
        SecureRandom random = new SecureRandom();
        for (int round = 0; round < 50; round++) {
            PlumaPathPolicy.Obfuscation o = PlumaPathPolicy.Obfuscation.create(random);
            byte[] h = o.header;
            check(h.length == 64 && h[0] != (byte) 0xef, "header");
            byte[] reversed = new byte[48];
            for (int a = 0; a < 48; a++) {
                reversed[a] = h[55 - a];
            }
            Cipher serverIn = PlumaPathPolicy.Obfuscation.ctr(Arrays.copyOfRange(h, 8, 40), Arrays.copyOfRange(h, 40, 56));
            Cipher serverOut = PlumaPathPolicy.Obfuscation.ctr(Arrays.copyOfRange(reversed, 0, 32), Arrays.copyOfRange(reversed, 32, 48));
            byte[] plainHeader = serverIn.update(h);
            check(hex(plainHeader, 56, 60).equals("eeeeeeee"), "the tag of the intermediate transport");
            byte[] message = PlumaPathPolicy.frame(PlumaPathPolicy.reqPqMulti(4, seq16()));
            check(Arrays.equals(serverIn.update(o.seal(message)), message), "client to server");
            byte[] answer = new byte[100];
            random.nextBytes(answer);
            byte[] sealed = serverOut.update(answer);
            byte[] opened = new byte[100];
            byte[] a = o.open(sealed, 0, 37);
            byte[] b = o.open(sealed, 37, 63);
            System.arraycopy(a, 0, opened, 0, a.length);
            System.arraycopy(b, 0, opened, a.length, b.length);
            check(Arrays.equals(opened, answer), "server to client, in pieces");
        }
    }

    static byte[] resPq(byte[] nonce) {
        ByteBuffer body = ByteBuffer.allocate(4 + 16 + 16 + 12 + 16).order(ByteOrder.LITTLE_ENDIAN);
        body.putInt(PlumaPathPolicy.RES_PQ).put(nonce).put(new byte[16]).put(PlumaPathPolicy.tlBytes(new byte[8]));
        body.putInt(0x1cb5c415).putInt(1).putLong(0x0123456789abcdefL);
        return PlumaPathPolicy.frame(PlumaPathPolicy.unencrypted(1, body.array()));
    }

    // The gateway's answer: total pluma.probeData, each pad 16384 bytes but the last.
    static List<byte[]> answer(byte[] nonce, int down) {
        int d = PlumaPathPolicy.clampDown(down);
        int total = PlumaPathPolicy.chunks(d);
        List<byte[]> out = new ArrayList<>();
        for (int seq = 0; seq < total; seq++) {
            int pad = seq == total - 1 ? d - 16384 * (total - 1) : 16384;
            byte[] bytes = PlumaPathPolicy.tlBytes(new byte[pad]);
            ByteBuffer body = ByteBuffer.allocate(36 + bytes.length).order(ByteOrder.LITTLE_ENDIAN);
            body.putInt(PlumaPathPolicy.PROBE_DATA).put(nonce).putInt(seq).putInt(total).putLong(1_700_000_000_000L).put(bytes);
            out.add(PlumaPathPolicy.frame(PlumaPathPolicy.unencrypted(5, body.array())));
        }
        return out;
    }

    static byte[] join(List<byte[]> parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        ByteBuffer out = ByteBuffer.allocate(n);
        for (byte[] p : parts) {
            out.put(p);
        }
        return out.array();
    }

    private static void reader() {
        byte[] request = seq16();
        byte[] probe = new byte[16];
        Arrays.fill(probe, (byte) 7);
        List<byte[]> chunks = answer(probe, 65536);
        check(chunks.size() == 4 && chunks.get(0).length == 4 + 16444, "a full chunk is 16444 bytes");
        byte[] head = resPq(request);
        byte[] all = join(Arrays.asList(head, join(chunks)));
        Random random = new Random(1);
        for (int round = 0; round < 200; round++) {
            PlumaPathPolicy.Reader r = new PlumaPathPolicy.Reader(request, probe, 65536);
            int answer = 0;
            for (int at = 0; at < all.length; ) {
                int n = Math.min(all.length - at, 1 + random.nextInt(round % 2 == 0 ? 40 : 20000));
                answer += r.feed(all, at, n);
                at += n;
            }
            check(r.done && r.error == null && r.resPq, "the whole answer in pieces");
            check(answer == all.length - head.length, "the answer's bytes are those after resPQ");
        }
        // 20000 bytes: two chunks, the last of 3616.
        PlumaPathPolicy.Reader odd = new PlumaPathPolicy.Reader(request, probe, 20000);
        byte[] oddAll = join(Arrays.asList(head, join(answer(probe, 20000))));
        odd.feed(oddAll, 0, oddAll.length);
        check(odd.done && odd.error == null, "a remainder chunk");
        // Errors: a wrong nonce of resPQ, of a chunk, a seq out of order, a chunk of another size,
        // a transport error code, an encrypted message.
        List<byte[]> wrong = new ArrayList<>();
        wrong.add(join(Arrays.asList(resPq(probe), join(chunks))));
        wrong.add(join(Arrays.asList(head, join(answer(request, 65536)))));
        List<byte[]> swapped = new ArrayList<>(chunks);
        Collections.swap(swapped, 0, 1);
        wrong.add(join(Arrays.asList(head, join(swapped))));
        wrong.add(join(Arrays.asList(head, join(answer(probe, 49152)))));
        wrong.add(join(Arrays.asList(head, PlumaPathPolicy.frame(new byte[]{(byte) 0x6c, (byte) 0xfe, (byte) 0xff, (byte) 0xff}))));
        byte[] encrypted = resPq(request);
        encrypted[4] = 1;
        wrong.add(encrypted);
        // The length of a pad written without its 0xfe.
        byte[] prefix = chunks.get(0).clone();
        prefix[4 + 20 + 36] = (byte) 0xfd;
        wrong.add(join(Arrays.asList(head, prefix)));
        for (byte[] w : wrong) {
            PlumaPathPolicy.Reader r = new PlumaPathPolicy.Reader(request, probe, 65536);
            r.feed(w, 0, w.length);
            check(r.error != null && !r.done, "a protocol error");
        }
        // The answer of 65536 is not done before its last chunk.
        PlumaPathPolicy.Reader part = new PlumaPathPolicy.Reader(request, probe, 65536);
        byte[] three = join(Arrays.asList(head, join(chunks.subList(0, 3))));
        part.feed(three, 0, three.length);
        check(!part.done && part.error == null && part.received == 3, "three chunks of four");
    }

    private static PlumaPathPolicy.Reader started(PlumaPathPolicy.Measure m, long at) {
        byte[] request = seq16();
        PlumaPathPolicy.Reader r = new PlumaPathPolicy.Reader(request, request, 65536);
        m.connected(at, false);
        m.requestSent(at);
        return r;
    }

    private static void measure() {
        PlumaPathPolicy.Params p = PlumaPathPolicy.Params.defaults();
        byte[] head = resPq(seq16());
        List<byte[]> chunks = answer(seq16(), 65536);

        // ok: resPQ at 100 ms, the four chunks at 300, 400, 500, 600.
        PlumaPathPolicy.Measure ok = new PlumaPathPolicy.Measure(p, 0);
        PlumaPathPolicy.Reader r = started(ok, 50);
        ok.received(150, head.length, r.feed(head, 0, head.length), r);
        ok.probeSent(151);
        check(ok.outcome(200) == null, "running");
        for (int i = 0; i < 4; i++) {
            byte[] c = chunks.get(i);
            ok.received(300 + 100 * i, c.length, r.feed(c, 0, c.length), r);
        }
        check(ok.outcome(600) == PlumaPathPolicy.Outcome.OK, "ok");
        check(ok.rtt() == 100, "rtt from req_pq_multi to resPQ");
        check(Math.abs(ok.bytesPerSecond() - 3 * 16448 * 1000.0 / 300) < 1e-6, "bps after the first read");
        check(Math.abs(PlumaPathPolicy.score(ok.rtt(), ok.bytesPerSecond()) - (100 + 262144 * 1000.0 / (3 * 16448 * 1000.0 / 300))) < 1e-6, "score");

        // Frozen after resPQ and one chunk: 1.5 s with no byte.
        PlumaPathPolicy.Measure frozen = new PlumaPathPolicy.Measure(p, 0);
        r = started(frozen, 50);
        frozen.received(150, head.length, r.feed(head, 0, head.length), r);
        frozen.probeSent(151);
        frozen.received(300, chunks.get(0).length, r.feed(chunks.get(0), 0, chunks.get(0).length), r);
        check(frozen.outcome(1799) == null, "not frozen before stall_ms");
        check(frozen.outcome(1800) == PlumaPathPolicy.Outcome.FROZEN, "frozen after stall_ms");

        // A probe that never reaches the gateway: the stall counts from the write plus rtt.
        PlumaPathPolicy.Measure up = new PlumaPathPolicy.Measure(p, 0);
        r = started(up, 50);
        up.received(1000, head.length, r.feed(head, 0, head.length), r);
        up.probeSent(1001);
        check(up.outcome(2900) == null, "the stall waits for the write plus rtt");
        check(up.outcome(1001 + 950 + 1500) == PlumaPathPolicy.Outcome.FROZEN, "frozen on the way up");

        // The WebSocket handshake is a byte: no resPQ in stall_ms after it is frozen.
        PlumaPathPolicy.Measure ws = new PlumaPathPolicy.Measure(p, 0);
        ws.connected(200, true);
        ws.requestSent(200);
        check(ws.outcome(1699) == null, "the handshake, then waiting");
        check(ws.outcome(1900) == PlumaPathPolicy.Outcome.FROZEN, "frozen after the handshake");

        // No byte at all: failed at the deadline, not frozen.
        PlumaPathPolicy.Measure silent = new PlumaPathPolicy.Measure(p, 0);
        started(silent, 50);
        check(silent.outcome(5999) == null, "no byte, waiting");
        check(silent.outcome(6000) == PlumaPathPolicy.Outcome.FAILED, "no byte by the deadline");

        // A close right after resPQ: the gateway does not know the probe.
        PlumaPathPolicy.Measure old = new PlumaPathPolicy.Measure(p, 0);
        r = started(old, 50);
        old.received(150, head.length, r.feed(head, 0, head.length), r);
        old.probeSent(151);
        old.closed();
        check(old.outcome(160) == PlumaPathPolicy.Outcome.UNSUPPORTED, "unsupported");
        // A close after a chunk, or before resPQ, is a failure.
        PlumaPathPolicy.Measure cut = new PlumaPathPolicy.Measure(p, 0);
        r = started(cut, 50);
        cut.received(150, head.length, r.feed(head, 0, head.length), r);
        cut.probeSent(151);
        cut.received(300, 100, r.feed(chunks.get(0), 0, 100), r);
        cut.closed();
        check(cut.outcome(310) == PlumaPathPolicy.Outcome.FAILED, "closed during the answer");
        PlumaPathPolicy.Measure refused = new PlumaPathPolicy.Measure(p, 0);
        started(refused, 50);
        refused.closed();
        check(refused.outcome(60) == PlumaPathPolicy.Outcome.FAILED, "closed before resPQ");

        // Slow: bytes keep coming, but not all of them by the deadline.
        PlumaPathPolicy.Measure slow = new PlumaPathPolicy.Measure(p, 0);
        r = started(slow, 50);
        slow.received(150, head.length, r.feed(head, 0, head.length), r);
        slow.probeSent(151);
        byte[] first = chunks.get(0);
        for (int i = 0, at = 0; at < first.length; i++, at += 1000) {
            int n = Math.min(1000, first.length - at);
            slow.received(500 + 1000L * i, n, r.feed(first, at, n), r);
        }
        check(slow.outcome(6000) == PlumaPathPolicy.Outcome.SLOW, "slow");
        check(slow.bytesPerSecond() > 0 && slow.bytesPerSecond() < 1100, "the speed of a slow path");

        // A protocol error.
        PlumaPathPolicy.Measure bad = new PlumaPathPolicy.Measure(p, 0);
        r = started(bad, 50);
        byte[] junk = new byte[]{4, 0, 0, 0, 1, 2, 3, 4};
        bad.received(100, junk.length, r.feed(junk, 0, junk.length), r);
        check(bad.outcome(100) == PlumaPathPolicy.Outcome.FAILED, "a protocol error fails");
    }

    private static Map<String, Object> server() {
        Map<String, Object> m = new HashMap<>();
        m.put("v", 1.0);
        m.put("country", "RU");
        for (int i = 0; i < PlumaPathPolicy.Params.NAMES.length; i++) {
            m.put(PlumaPathPolicy.Params.NAMES[i], PlumaPathPolicy.Params.DEFAULTS[i]);
        }
        return m;
    }

    private static void params() {
        PlumaPathPolicy.Params d = PlumaPathPolicy.Params.defaults();
        check(d.gateDown() == 65536 && d.rankDown() == 196608 && d.up() == 20480 && d.stallMs() == 1500
                && d.deadlineMs() == 6000 && d.suspectMs() == 4000 && d.reprobeMs() == 21_600_000L
                && d.rankMinIntervalMs() == 1_800_000L && d.minDwellMs() == 600_000L && d.switchRatio() == 0.7
                && d.switchRatioNow() == 0.25 && d.edgeProbeIfDirectMs() == 1500 && d.badTtlMs() == 86_400_000L
                && d.failedTtlMs() == 300_000L && d.raceStaggerMs() == 800 && d.confirmMs() == 60_000L
                && d.country.isEmpty(), "the defaults of the brief");
        PlumaPathPolicy.Params s = PlumaPathPolicy.Params.of(server());
        check(s != null && s.country.equals("RU") && s.gateDown() == 65536, "the server's object");
        check(s.equals(PlumaPathPolicy.Params.fromText(s.toText())), "text round trip");
        Map<String, Object> partial = new HashMap<>();
        partial.put("v", 1.0);
        partial.put("stall_ms", 2000.0);
        PlumaPathPolicy.Params q = PlumaPathPolicy.Params.of(partial);
        check(q != null && q.stallMs() == 2000 && q.deadlineMs() == 6000 && q.country.isEmpty(), "a missing field takes its default");
        Map<String, Object> extra = server();
        extra.put("future_field", "x");
        check(PlumaPathPolicy.Params.of(extra) != null, "an unknown field is skipped");
        Object[][] bad = {
            {"v", 2.0}, {"v", "1"}, {"v", null}, {"country", "ru"}, {"country", "RUS"}, {"country", 1.0},
            {"gate_down", 16383.0}, {"gate_down", 524289.0}, {"gate_down", 65536.5}, {"up", 65537.0},
            {"stall_ms", 6000.0}, {"deadline_ms", 1500.0}, {"switch_ratio", 0.2}, {"switch_ratio_now", 0.96},
            {"confirm_s", "60"}, {"race_stagger_ms", -1.0}, {"bad_ttl_s", Double.NaN},
        };
        for (Object[] b : bad) {
            Map<String, Object> m = server();
            if (b[1] == null) {
                m.remove(b[0]);
            } else {
                m.put((String) b[0], b[1]);
            }
            check(PlumaPathPolicy.Params.of(m) == null, "not valid: " + b[0] + " " + b[1]);
        }
        check(PlumaPathPolicy.Params.fromText("nonsense") == null, "a text toText did not write");
    }

    private static void decisions() {
        PlumaPathPolicy.Params p = PlumaPathPolicy.Params.defaults();
        List<String> order = Arrays.asList("direct", "wss://a/apiws", "wss://b/apiws");
        Map<String, Double> scores = new HashMap<>();
        check(PlumaPathPolicy.best(order, scores) == null, "nothing scored");
        scores.put("wss://a/apiws", 100.0);
        scores.put("wss://b/apiws", 50.0);
        check("wss://b/apiws".equals(PlumaPathPolicy.best(order, scores)), "the lowest score");
        scores.put("direct", 64.0);
        check("direct".equals(PlumaPathPolicy.best(order, scores)), "a tie within 30 % goes by order");
        scores.put("direct", 66.0);
        check("wss://b/apiws".equals(PlumaPathPolicy.best(order, scores)), "beyond 30 % the score wins");

        long dwell = p.minDwellMs();
        check(PlumaPathPolicy.decide(1000, 250, false, dwell, p) == PlumaPathPolicy.Decision.SWITCH, "0.25: at once");
        check(PlumaPathPolicy.decide(1000, 251, false, dwell, p) == PlumaPathPolicy.Decision.CONFIRM, "0.7: confirm first");
        check(PlumaPathPolicy.decide(1000, 700, true, dwell, p) == PlumaPathPolicy.Decision.SWITCH, "0.7 twice: switch");
        check(PlumaPathPolicy.decide(1000, 701, true, dwell, p) == PlumaPathPolicy.Decision.STAY, "above 0.7: stay");
        check(PlumaPathPolicy.decide(1000, 100, true, dwell - 1, p) == PlumaPathPolicy.Decision.STAY, "within min_dwell_s: stay");
        check(PlumaPathPolicy.decide(1000, Double.POSITIVE_INFINITY, true, dwell, p) == PlumaPathPolicy.Decision.STAY, "an unscored candidate");

        check(PlumaPathPolicy.rankEdges(true, PlumaPathPolicy.Outcome.OK, 10, p), "the country puts the edges first");
        check(PlumaPathPolicy.rankEdges(false, PlumaPathPolicy.Outcome.FROZEN, 10, p), "the direct path froze");
        check(PlumaPathPolicy.rankEdges(false, PlumaPathPolicy.Outcome.OK, 1501, p), "the direct path is slow");
        check(!PlumaPathPolicy.rankEdges(false, PlumaPathPolicy.Outcome.OK, 1500, p), "the direct path is good: no edge");
    }

    private static void memory() {
        PlumaPathPolicy.Params p = PlumaPathPolicy.Params.defaults();
        long now = 1_700_000_000_000L;
        List<String> direct = Arrays.asList("direct", "wss://a.example/apiws", "wss://b.example/apiws");
        List<String> edges = Arrays.asList("wss://a.example/apiws", "wss://b.example/apiws", "direct");
        PlumaPathPolicy.Network n = new PlumaPathPolicy.Network();
        check(n.order(direct, now).equals(direct), "no memory: pluma_edge's order");
        check(n.firstGroup(direct, now).equals(Collections.singletonList("direct")), "no memory, direct first");
        check(n.firstGroup(edges, now).equals(Arrays.asList("wss://a.example/apiws", "wss://b.example/apiws")), "no memory, edges first");

        n.record("direct", PlumaPathPolicy.Outcome.FROZEN, Double.NaN, now, p);
        n.record("wss://b.example/apiws", PlumaPathPolicy.Outcome.OK, 300, now, p);
        n.best = "wss://b.example/apiws";
        check(n.excluded("direct", now + p.badTtlMs() - 1) && !n.excluded("direct", now + p.badTtlMs()), "frozen: bad_ttl_s");
        check(n.order(direct, now + 1).equals(Arrays.asList("wss://b.example/apiws", "wss://a.example/apiws", "direct")), "the best first, the excluded last");
        check(n.firstGroup(direct, now + 1).equals(Collections.singletonList("wss://b.example/apiws")), "fresh memory: the best alone");
        long stale = now + PlumaPathPolicy.FRESH_MS + 1;
        check(n.order(direct, stale).equals(direct), "stale memory: pluma_edge's order");
        n.record("direct", PlumaPathPolicy.Outcome.OK, 100, now + 2, p);
        check(!n.excluded("direct", now + 3), "ok clears the exclusion");
        n.record("wss://a.example/apiws", PlumaPathPolicy.Outcome.FAILED, Double.NaN, now, p);
        check(n.excluded("wss://a.example/apiws", now + p.failedTtlMs() - 1) && !n.excluded("wss://a.example/apiws", now + p.failedTtlMs()), "failed: failed_ttl_s");

        PlumaPathPolicy.PathState s = new PlumaPathPolicy.PathState();
        check(s.effectiveScore() == Double.POSITIVE_INFINITY, "no score");
        PlumaPathPolicy.Network m = new PlumaPathPolicy.Network();
        m.record("direct", PlumaPathPolicy.Outcome.OK, 100, now, p);
        m.record("direct", PlumaPathPolicy.Outcome.SLOW, 120, now, p);
        check(m.state("direct").effectiveScore() == 120, "one loss: no penalty");
        m.record("direct", PlumaPathPolicy.Outcome.SLOW, 130, now, p);
        check(m.state("direct").effectiveScore() == 260, "two losses of four: twice");
        m.record("direct", PlumaPathPolicy.Outcome.OK, 100, now, p);
        m.record("direct", PlumaPathPolicy.Outcome.OK, 100, now, p);
        m.record("direct", PlumaPathPolicy.Outcome.OK, 100, now, p);
        check(m.state("direct").effectiveScore() == 100, "the losses left the window");

        PlumaPathPolicy.Memory memory = new PlumaPathPolicy.Memory();
        PlumaPathPolicy.Network a = memory.network("RU:0011223344556677");
        a.best = "wss://ru.example/a b?c=d&e";
        a.ranked = now - 5;
        a.switched = now - 6;
        a.record("wss://ru.example/a b?c=d&e", PlumaPathPolicy.Outcome.OK, 123.5, now, p);
        a.record("direct", PlumaPathPolicy.Outcome.FROZEN, Double.NaN, now, p);
        PlumaPathPolicy.Memory back = PlumaPathPolicy.Memory.fromText(memory.toText());
        check(back.toText().equals(memory.toText()), "memory text round trip");
        PlumaPathPolicy.Network b = back.networks.get("RU:0011223344556677");
        check(b != null && a.best.equals(b.best) && b.state(a.best).score == 123.5 && b.excluded("direct", now + 1)
                && b.ranked == now - 5 && b.switched == now - 6, "memory fields");
        check(PlumaPathPolicy.Memory.fromText("n x").networks.isEmpty(), "a broken text is no memory");
        check(PlumaPathPolicy.Memory.fromText("p direct 1 OK 1 0 1 0\n").networks.isEmpty(), "a path without a network");
        check(PlumaPathPolicy.Memory.fromText("").networks.isEmpty(), "an empty text");
        PlumaPathPolicy.Memory many = new PlumaPathPolicy.Memory();
        for (int i = 0; i < 20; i++) {
            many.network("DE:" + i).used = now + i;
        }
        many.prune();
        check(many.networks.size() == 16 && !many.networks.containsKey("DE:3") && many.networks.containsKey("DE:4"), "at most 16, the oldest go");
    }

    private static void networkKey() {
        String a = PlumaPathPolicy.networkKey("RU", "wifi", Arrays.asList("gw=192.168.1.1", "dns=192.168.1.1"));
        String b = PlumaPathPolicy.networkKey("RU", "wifi", Arrays.asList("dns=192.168.1.1", "gw=192.168.1.1"));
        check(a.equals(b), "the order of the parts does not matter");
        check(a.matches("RU:[0-9a-f]{16}"), "country and 16 hex digits");
        check(!a.contains("192.168"), "no raw address");
        check(!a.equals(PlumaPathPolicy.networkKey("DE", "wifi", Arrays.asList("gw=192.168.1.1", "dns=192.168.1.1"))), "another country");
        check(!a.equals(PlumaPathPolicy.networkKey("RU", "cellular", Arrays.asList("gw=192.168.1.1", "dns=192.168.1.1"))), "another transport");
        check(PlumaPathPolicy.networkKey("", "none", Collections.<String>emptyList()).startsWith(":"), "no country yet");
    }
}
