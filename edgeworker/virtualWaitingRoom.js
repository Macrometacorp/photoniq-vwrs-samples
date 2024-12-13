/**
 * Copyright (c) 2023 Macrometa Corporation. All Rights Reserved
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

import { logger } from 'log';
import { crypto } from 'crypto';
import { httpRequest } from 'http-request';
import { Cookies, SetCookie } from 'cookies';
import { TextEncoder, base64, TextDecoder } from 'encoding';

var OriginAccessMode;
(function (OriginAccessMode) {
    OriginAccessMode["ORIGIN_USAGE_TIME"] = "ORIGIN_USAGE_TIME";
    OriginAccessMode["ORIGIN_IDLE_TIME"] = "ORIGIN_IDLE_TIME";
})(OriginAccessMode || (OriginAccessMode = {}));
const VwrDefaults = {
    VWRS_SUFFIX: "/api/vwr/v1",
    METRIC_SUFFIX: "/api/vwr/v1/metrics/origin",
    WAITING_ROOM_ORIGIN: "waitingroom",
    ORIGIN_ACCESS_MODE: OriginAccessMode.ORIGIN_USAGE_TIME,
    RETRY_LIMIT: 0,
    PRIORITY: 0,
    BACK_OFF_THRESHOLD: 0.85,
    NO_BACK_OFF_THRESHOLD: 5,
    REQUEST_TIMEOUT: 4500,
};
const VWRoomVersion = "2.2.0";
var HttpMethods;
(function (HttpMethods) {
    HttpMethods["GET"] = "GET";
    HttpMethods["POST"] = "POST";
})(HttpMethods || (HttpMethods = {}));
var HttpStatusCodes;
(function (HttpStatusCodes) {
    HttpStatusCodes[HttpStatusCodes["OK"] = 200] = "OK";
    HttpStatusCodes[HttpStatusCodes["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
    HttpStatusCodes[HttpStatusCodes["REDIRECT"] = 302] = "REDIRECT";
    HttpStatusCodes[HttpStatusCodes["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    HttpStatusCodes[HttpStatusCodes["NOT_FOUND"] = 404] = "NOT_FOUND";
})(HttpStatusCodes || (HttpStatusCodes = {}));
var EwPaths;
(function (EwPaths) {
    EwPaths["ROOT"] = "/";
    EwPaths["STATUS"] = "/queue-status";
    EwPaths["PREVIEW"] = "/preview";
})(EwPaths || (EwPaths = {}));
var Headers;
(function (Headers) {
    Headers["CONTENT_TYPE"] = "Content-Type";
    Headers["CACHE"] = "Cache-Control";
    Headers["COOKIE"] = "Cookie";
    Headers["SET_COOKIE"] = "Set-Cookie";
    Headers["AUTH"] = "authorization";
    Headers["NO_WAITING_ROOM"] = "NO-WAITING-ROOM";
    Headers["INSECURE"] = "INSECURE";
    Headers["NO_TOKEN_FOUND"] = "NO-TOKEN-FOUND";
    Headers["X_VWRS_DEBUG"] = "X-VWRS-DEBUG";
    Headers["X_SUB_REQUEST_COUNT"] = "X-SUBREQUEST-COUNT";
})(Headers || (Headers = {}));
var MimeTypes;
(function (MimeTypes) {
    MimeTypes["HTML"] = "text/html";
    MimeTypes["JSON"] = "application/json";
})(MimeTypes || (MimeTypes = {}));
var CacheValues;
(function (CacheValues) {
    CacheValues["NO_CACHE"] = "max-age=0, private, no-store, no-cache, must-revalidate";
})(CacheValues || (CacheValues = {}));
var TransportVariables;
(function (TransportVariables) {
    TransportVariables["STATUS_CODE"] = "PMUSER_VSC";
    TransportVariables["FLOW"] = "PMUSER_FL";
    TransportVariables["AVG_WAITING_TIME"] = "PMUSER_AWT";
    TransportVariables["VWRS_PERSIST"] = "PMUSER_VP";
    TransportVariables["REQUEST_COUNT"] = "PMUSER_RC";
})(TransportVariables || (TransportVariables = {}));
/**
 * Try to follow the nomenclature:
 * TYPE OBJECT VERB/ADJECTIVE
 */
var StatusCode;
(function (StatusCode) {
    // ERROR status code
    StatusCode["ERROR_HTTP_WAITINGROOM_DETAILS"] = "EHWD";
    StatusCode["ERROR_HTTP_REQ_STATUS"] = "EHRS";
    StatusCode["ERROR_HTTP_REQ_PUSH"] = "EHRP";
    StatusCode["ERROR_HTTP_METRIC_NOTIFY"] = "EHMN";
    StatusCode["ERROR_HTTP_QUEUE_DEPTH"] = "EHQD";
    StatusCode["ERROR_SECURITY_COOKIE_ENCRYPTION"] = "ESCE";
    StatusCode["ERROR_SECURITY_COOKIE_DECRYPTION"] = "ESCD";
    StatusCode["ERROR_SECURITY_COOKIE_CREATED_AT"] = "ESCC";
    StatusCode["ERROR_SECURITY_DIGEST_CREATE"] = "ESDC";
    StatusCode["ERROR_SECURITY_TOKEN_EXISTENCE"] = "ESTE";
    StatusCode["ERROR_SECURITY_ENCRYPTION_RAW_KEY"] = "ESER";
    // SUCCESS status code
    StatusCode["SUCCESS_ROUTE_ORIGIN_LIVE"] = "SROL";
    StatusCode["SUCCESS_ROUTE_WAITING_LIVE"] = "SRWL";
    StatusCode["SUCCESS_ROUTE_WAITING_PREVIEW"] = "SRWP";
    StatusCode["SUCCESS_HTTP_STATUS_LIVE"] = "SHSL";
    StatusCode["SUCCESS_HTTP_STATUS_PREVIEW"] = "SHSP";
})(StatusCode || (StatusCode = {}));
// how the EW request/response should be handled
var Flow;
(function (Flow) {
    Flow["NO_WAITING_ROOM"] = "NWR";
    Flow["INSECURE"] = "IS";
    Flow["NORMAL"] = "NO";
    Flow["INGRESS_ERROR"] = "IE";
})(Flow || (Flow = {}));
// how EW treats the request internally
var RequestType;
(function (RequestType) {
    RequestType[RequestType["NEW_REQUEST"] = 0] = "NEW_REQUEST";
    RequestType[RequestType["EXISTING_REQUEST"] = 1] = "EXISTING_REQUEST";
})(RequestType || (RequestType = {}));
var CookieIdentifier;
(function (CookieIdentifier) {
    CookieIdentifier["SESSION"] = "vwrs-session";
})(CookieIdentifier || (CookieIdentifier = {}));
const VwrDurations = {
    accessMaxAgeInSec: 10 * 60,
    getSessionMaxAgeSec(avgWaitingTime = "") {
        const avgWaitingTimeValue = parseInt(avgWaitingTime, 10);
        const isValidNumber = typeof avgWaitingTimeValue === "number" && !isNaN(avgWaitingTimeValue);
        const baseWaitingTime = isValidNumber
            ? avgWaitingTimeValue
            : this.defaultWaitingTime;
        return baseWaitingTime + this.bufferTimeSec;
    },
    defaultWaitingTime: 1,
    bufferTimeSec: 120,
    get currentTime() {
        return Date.now();
    },
    getCookieExpireAt(maxAge) {
        return this.currentTime + maxAge * 1000;
    },
    getTimeElapsedSec(grantedAt) {
        return Math.ceil((this.currentTime - grantedAt) / 1000);
    },
};
var MetricsNotificationType;
(function (MetricsNotificationType) {
    MetricsNotificationType["EDGEWORKER"] = "EW";
    MetricsNotificationType["WAITING_ROOM"] = "PAGE";
})(MetricsNotificationType || (MetricsNotificationType = {}));
var GoingTo;
(function (GoingTo) {
    GoingTo["ORIGIN"] = "ORIGIN";
    GoingTo["WAITING"] = "WAITING ROOM";
})(GoingTo || (GoingTo = {}));
var TokenType;
(function (TokenType) {
    TokenType["SESSION"] = "S";
    TokenType["ACCESS"] = "A";
})(TokenType || (TokenType = {}));
var Encryption;
(function (Encryption) {
    Encryption["ALGORITHM"] = "AES-CBC";
    Encryption["DELIMITER"] = ":";
    Encryption["DECRYPTION_FAILED"] = "D_FAIL";
})(Encryption || (Encryption = {}));
var DequeueMode;
(function (DequeueMode) {
    DequeueMode["ON"] = "on";
    DequeueMode["OFF"] = "off";
})(DequeueMode || (DequeueMode = {}));
const PreviewStatusResponse = {
    REQ_ID: "R-b69f3f06-6055-4c2a-947f-d74f316d479f",
    PREVIEW_DATA_OBJ: {
        avg_waiting_time: 100,
        queue_depth: 200,
        position: 100,
        waiting_room_interval: 500,
        dequeue_mode: DequeueMode.ON
    },
};
const keyMappings = {
    waitingroomDetails: "wd",
    max_origin_usage_time: "ad",
    waiting_room_path: "wrp",
    is_queue_enabled: "qe",
    waitingroom_key: "wk",
    waitingroom_url: "wu",
    requestDetails: "rd",
    priority: "p",
    reqId: "r",
    sid: "s",
    created_at: "ca",
    lastReqTime: "lrq",
    nextCallTime: "nct",
    curPos: "cp",
    rLimit: "rl",
    qDepth: "qd",
    statInt: "si",
    createdAt: "c",
    type: "t",
    meta: "m",
    delayTime: "dt",
    dequeue_mode: "dm",
};

class Connection {
    static instance;
    _vwrsURL;
    _vwrsMetricUrl;
    _apiKey;
    _isFailOpen;
    _digestKey;
    _encryptionKey;
    _originAccessMode;
    _retryLimit;
    _backOffThreshold;
    _noBackOffThreshold;
    _requestTimeout;
    _statusConfigLimits = {
        avgWaitingTime: false,
        qDepth: false,
        position: false,
    };
    constructor(config) {
        const { apiKey, isFailOpen, digestKey, encryptionKey, originAccessMode, statusConfigLimits, retryLimit, backOffThreshold, noBackOffThreshold, requestTimeout, } = config;
        const errors = this.validate(config);
        if (errors.length > 0) {
            throw new Error(JSON.stringify(errors));
        }
        const vwrs = config.vwrsHost ||
            config.vwrsURL;
        this._vwrsURL = this.buildMMUrl(vwrs, VwrDefaults.VWRS_SUFFIX);
        const metric = config.vwrsMetricHost ||
            config.vwrsMetricUrl;
        this._vwrsMetricUrl = this.buildMMUrl(metric, VwrDefaults.METRIC_SUFFIX);
        this._apiKey = apiKey;
        this._isFailOpen = isFailOpen !== false;
        this._digestKey = digestKey;
        this._encryptionKey = encryptionKey;
        this._originAccessMode =
            originAccessMode?.toUpperCase() ||
                VwrDefaults.ORIGIN_ACCESS_MODE;
        this._retryLimit = retryLimit || VwrDefaults.RETRY_LIMIT;
        this._backOffThreshold = backOffThreshold || VwrDefaults.BACK_OFF_THRESHOLD;
        this._noBackOffThreshold =
            noBackOffThreshold || VwrDefaults.NO_BACK_OFF_THRESHOLD;
        this._requestTimeout = requestTimeout || VwrDefaults.REQUEST_TIMEOUT;
        this.processUiLimits(statusConfigLimits);
    }
    validate(config) {
        const errors = [];
        const { apiKey, digestKey, encryptionKey } = config;
        if (!config.vwrsHost &&
            !config.vwrsURL) {
            errors.push("One of 'vwrsHost' or 'vwrsURL' should be given");
        }
        if (!config.vwrsMetricHost &&
            !config.vwrsMetricUrl) {
            errors.push("One of 'vwrsMetricHost' or 'vwrsMetricUrl' should be given");
        }
        if (!apiKey) {
            errors.push("'apiKey' is a required field");
        }
        if (!digestKey) {
            errors.push("'digestKey' is a required field");
        }
        if (!encryptionKey) {
            errors.push("'encryptionKey' is a required field");
        }
        return errors;
    }
    buildMMUrl = (url, suffix) => {
        // Remove "https://" if present
        let waitingroom = url.replace("https://", "");
        // Remove any trailing slashes
        waitingroom = waitingroom.replace(/\/+$/, "");
        return `https://${waitingroom}${suffix}`;
    };
    processUiLimits(statusConfigLimits) {
        if (statusConfigLimits) {
            for (let key in statusConfigLimits) {
                if (key in this._statusConfigLimits) {
                    const uiConfigKey = key;
                    const value = statusConfigLimits[uiConfigKey];
                    if (typeof value !== "boolean") {
                        continue;
                    }
                    this._statusConfigLimits[uiConfigKey] = value;
                }
            }
        }
    }
    static createInstance(config) {
        if (!Connection.instance) {
            Connection.instance = new Connection(config);
        }
    }
    static getInstance() {
        return Connection.instance;
    }
    updateConfig(config) {
        const { apiKey, isFailOpen, digestKey, encryptionKey, statusConfigLimits, retryLimit, backOffThreshold, noBackOffThreshold, requestTimeout, } = config;
        if (apiKey !== undefined) {
            Connection.instance._apiKey = apiKey;
        }
        const vwrs = config.vwrsHost ||
            config.vwrsURL;
        if (vwrs !== undefined) {
            Connection.instance._vwrsURL = this.buildMMUrl(vwrs, VwrDefaults.VWRS_SUFFIX);
        }
        const metric = config.vwrsMetricHost ||
            config.vwrsMetricUrl;
        if (metric !== undefined) {
            Connection.instance._vwrsMetricUrl = this.buildMMUrl(metric, VwrDefaults.METRIC_SUFFIX);
        }
        if (isFailOpen !== undefined) {
            Connection.instance._isFailOpen = isFailOpen;
        }
        if (digestKey !== undefined) {
            Connection.instance._digestKey = digestKey;
        }
        if (encryptionKey !== undefined) {
            Connection.instance._encryptionKey = encryptionKey;
        }
        if (statusConfigLimits !== undefined) {
            Connection.instance.processUiLimits(statusConfigLimits);
        }
        if (retryLimit !== undefined) {
            Connection.instance._retryLimit = retryLimit;
        }
        if (noBackOffThreshold !== undefined) {
            Connection.instance._noBackOffThreshold = noBackOffThreshold;
        }
        if (backOffThreshold !== undefined) {
            Connection.instance._backOffThreshold = backOffThreshold;
        }
        if (requestTimeout !== undefined) {
            Connection.instance._requestTimeout = requestTimeout;
        }
    }
    get vwrMetricUrl() {
        return this._vwrsMetricUrl;
    }
    get vwrUrl() {
        return this._vwrsURL;
    }
    get apiKey() {
        return this._apiKey;
    }
    get isFailOpen() {
        return this._isFailOpen;
    }
    get digestKey() {
        return this._digestKey;
    }
    get encryptionKey() {
        return this._encryptionKey;
    }
    get originAccessMode() {
        return this._originAccessMode;
    }
    get statusConfigLimits() {
        return this._statusConfigLimits;
    }
    get retryLimit() {
        return this._retryLimit;
    }
    get backOffThreshold() {
        return this._backOffThreshold;
    }
    get noBackOffThreshold() {
        return this._noBackOffThreshold;
    }
    get requestTimeout() {
        return this._requestTimeout;
    }
}

const errorHandler = async (request, requestOpts = {}, isIngress, e) => {
    let errorMsg;
    if (e instanceof HttpError) {
        errorMsg = JSON.stringify({
            HttpError: true,
            status: e.status,
            context: e.context,
        });
    }
    else if (e instanceof Error) {
        errorMsg = e?.toString();
    }
    else {
        try {
            errorMsg = `Error of unknown type: ${e}`;
        }
        catch (err) {
            errorMsg = "Caught an exception but cannot print it";
        }
    }
    logger.log(`E:${errorMsg}`);
    isIngress && request.setVariable(TransportVariables.FLOW, Flow.INGRESS_ERROR);
    if (isIngress === true && Connection.getInstance().isFailOpen === true) {
        logger.log("FailOpen: true");
        const ingressRequest = request;
        const persistedData = getPersistedData(request);
        const reqId = persistedData?.meta?.requestDetails?.reqId ?? getUUID();
        const priority = VwrDefaults.PRIORITY;
        const waitingroom_key = persistedData?.meta?.waitingroomDetails?.waitingroom_key || "";
        const waitingroom_url = persistedData?.meta?.waitingroomDetails?.waitingroom_url || "";
        const dequeue_mode = persistedData?.meta?.waitingroomDetails?.dequeue_mode || DequeueMode.ON;
        persistData(ingressRequest, {
            meta: {
                requestDetails: { reqId, priority },
                waitingroomDetails: { waitingroom_key, is_queue_enabled: false, waitingroom_url, dequeue_mode },
            },
        });
        await gotoOrigin(ingressRequest);
    }
    else {
        request.respondWith(HttpStatusCodes.INTERNAL_SERVER_ERROR, {
            [Headers.CONTENT_TYPE]: MimeTypes.HTML,
            [Headers.CACHE]: CacheValues.NO_CACHE,
        }, errorMsg);
    }
};
const isHttpError = (e) => e?.isHttpError === true;
class HttpError extends Error {
    name = "HttpError";
    isHttpError = true;
    response;
    status;
    context;
    constructor(response, context) {
        super();
        this.response = response;
        this.status = response.status;
        this.context = context;
    }
}

/**
 * @param {number[]} ignoreHttpCodes - HTTP codes to not throw error
 * @param {number} retryCount - This is just for making recursive calls. Should not be used by calling function
 */
const httpHelper = async (request, context, fetcher, onFailStatusCode, throwErrorOnFail = true, ignoreHttpCodes = [], retryCount = 0) => {
    try {
        const reqCount = request.getVariable(TransportVariables.REQUEST_COUNT);
        request.setVariable(TransportVariables.REQUEST_COUNT, "" + (parseInt(reqCount) + 1));
        const res = await fetcher();
        logger.log("RStatus:%d", res.status);
        if (res.ok === true ||
            ignoreHttpCodes.find((code) => code === res.status)) {
            return res;
        }
        else {
            throw new HttpError(res, context);
        }
    }
    catch (e) {
        const { retryLimit } = Connection.getInstance();
        if (isHttpError(e) && retryCount < retryLimit) {
            logger.log("Retry:%d", retryCount + 1);
            return await httpHelper(request, context, fetcher, onFailStatusCode, true, ignoreHttpCodes, retryCount + 1);
        }
        else {
            request.setVariable(TransportVariables.STATUS_CODE, onFailStatusCode);
            if (throwErrorOnFail !== false) {
                throw e;
            }
            return e;
        }
    }
};
const getWaitingRoomDetails = async (request) => {
    const waitingRoomUrl = getWaitingRoom(request);
    logger.log("getWaitingRoomDetails:%s", waitingRoomUrl);
    const fetcher = () => httpRequest(`${Connection.getInstance().vwrUrl}/waitingrooms?url=${waitingRoomUrl}&wildcard=true&client_version=${VWRoomVersion}`, {
        method: HttpMethods.GET,
        headers: getHeadersWithAuth(),
        timeout: Connection.getInstance().requestTimeout,
    });
    return await httpHelper(request, "getWaitingRoomDetails", fetcher, StatusCode.ERROR_HTTP_WAITINGROOM_DETAILS, true, [HttpStatusCodes.NOT_FOUND]);
};
const pushRequestToQueue = async (request, requestType, reqId, waitingroom, priority) => {
    logger.log("pushRequestToQueue", reqId, waitingroom);
    const body = {
        waitingroom_key: waitingroom,
        region: getLocationDetails(request),
        request_time: Date.now(),
        duplicate: requestType === RequestType.EXISTING_REQUEST,
        priority,
    };
    const fetcher = () => httpRequest(`${Connection.getInstance().vwrUrl}/requests/${reqId}?client_version=${VWRoomVersion}`, {
        method: HttpMethods.POST,
        headers: getHeadersWithAuth(),
        body: JSON.stringify(body),
        timeout: Connection.getInstance().requestTimeout,
    });
    return await httpHelper(request, "pushRequestToQueue", fetcher, StatusCode.ERROR_HTTP_REQ_PUSH);
};
const getQueueStatusForRequest = async (request, reqId, waitingroom_key, sid, created_at, priority) => {
    const fetcher = () => httpRequest(`${Connection.getInstance().vwrUrl}/requests/status/${reqId}?waitingroom=${waitingroom_key}&sid=${sid}&created_at=${created_at}&priority=${priority}&client_version=${VWRoomVersion}`, {
        method: HttpMethods.GET,
        headers: getHeadersWithAuth(),
        timeout: Connection.getInstance().requestTimeout,
    });
    return await httpHelper(request, "getQueueStatusForRequest", fetcher, StatusCode.ERROR_HTTP_REQ_STATUS);
};
const notifyMetricServer = async (request, reqId, waitingroom_key) => {
    const body = {
        user_id: reqId,
        waitingroom_key: waitingroom_key,
        notificationType: getNotificationType(request),
        region: getLocationDetails(request),
    };
    const fetcher = () => httpRequest(Connection.getInstance().vwrMetricUrl, {
        method: HttpMethods.POST,
        headers: getHeadersWithAuth(),
        body: JSON.stringify(body),
        timeout: Connection.getInstance().requestTimeout,
    });
    return await httpHelper(request, "pushMetric", fetcher, StatusCode.ERROR_HTTP_METRIC_NOTIFY, false);
};

const getWaitingRoom = (req) => {
    return `${req.host}${getSanitizedPath(req)}`;
};
const getUUID = () => {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    // Set the version and variant fields according to UUIDv4 specifications
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    const toHex = (n) => n.toString(16).padStart(2, "0");
    return [
        ...buf.slice(0, 4),
        ...buf.slice(4, 6),
        ...buf.slice(6, 8),
        ...buf.slice(8, 10),
        ...buf.slice(10, 16),
    ]
        .map(toHex)
        .join("")
        .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5");
};
const isStatusPath = (request) => request.path.endsWith(EwPaths.STATUS);
const isPreviewPath = (request) => {
    return (request.path.endsWith(EwPaths.PREVIEW) ||
        request.path.endsWith(`${EwPaths.PREVIEW}${EwPaths.STATUS}`));
};
const getSanitizedPath = (request) => {
    const { path } = request;
    let purgedPath = isStatusPath(request)
        ? path.slice(0, -EwPaths.STATUS.length)
        : path;
    return purgedPath;
};
const getNotificationType = (request) => isStatusPath(request)
    ? MetricsNotificationType.WAITING_ROOM
    : MetricsNotificationType.EDGEWORKER;
const getLocationDetails = (request) => JSON.stringify(request.userLocation);
const buildStatusBody = (reqId, towards, reqStatus) => {
    const updatedReqStatus = formatReqStatusResponse(reqStatus);
    const statusBody = updatedReqStatus || {
        to: towards,
    };
    return JSON.stringify({ reqId, ...statusBody });
};
const getWaitingRoomPath = async (request, requestOpts) => {
    if (requestOpts?.waitingRoomPath) {
        return requestOpts.waitingRoomPath;
    }
    const result = await getWaitingRoomDetails(request).then((res) => res.json());
    if (result) {
        const { waiting_room_path } = result;
        if (waiting_room_path) {
            return waiting_room_path;
        }
    }
};
const getHeadersWithAuth = (headers = {}) => ({
    ...headers,
    [Headers.AUTH]: Connection.getInstance().apiKey,
});
const getPersistedData = (request) => {
    let data = request.getVariable(TransportVariables.VWRS_PERSIST);
    let parsedData = data ? JSON.parse(data) : undefined;
    if (!parsedData)
        return undefined;
    parsedData = mapKeysToLong(parsedData);
    parsedData = updateTimesAddCreatedAt(parsedData);
    return parsedData;
};
const persistCookieData = (request, debugMode, decryptedData) => {
    const data = JSON.parse(decryptedData);
    let filteredData = {
        meta: data?.meta,
        createdAt: data?.createdAt,
        type: data?.type,
    };
    filteredData = updateTimesSubtractCreatedAt(filteredData);
    filteredData = mapKeysToShort(filteredData);
    const stringified = JSON.stringify(filteredData);
    if (debugMode === true) {
        logger.log("Cookie persist data %s PMUser size %s", stringified, getPMUserLength(request) + stringified.length);
    }
    logger.log("PMUser current size %s + persis length %s", getPMUserLength(request), stringified.length);
    request.setVariable(TransportVariables.VWRS_PERSIST, stringified);
};
/**
 * @description Note: Only "gotoWaitingRoom" or "gotoOrigin" should call it
 */
const persistTokenType = (request, type) => {
    const originalData = getPersistedData(request) || {};
    let updatedData = {
        ...originalData,
        type: type ?? originalData.type,
    };
    updatedData = updateTimesSubtractCreatedAt(updatedData);
    updatedData = mapKeysToShort(updatedData);
    const stringified = JSON.stringify(updatedData);
    logger.log("PMUser current size %s + persis length %s", getPMUserLength(request), stringified.length);
    request.setVariable(TransportVariables.VWRS_PERSIST, stringified);
};
/**
 * @description "Only provide data to be updated. Especially for 'meta'"
 */
const persistData = (request, options = { meta: {} }) => {
    const originalData = getPersistedData(request) || {};
    let updatedData = {
        ...originalData,
        meta: {
            waitingroomDetails: {
                ...originalData?.meta?.waitingroomDetails,
                ...options?.meta?.waitingroomDetails,
            },
            requestDetails: {
                ...originalData?.meta?.requestDetails,
                ...options?.meta?.requestDetails,
            },
        },
        createdAt: options?.createdAt ?? originalData.createdAt,
    };
    updatedData = updateTimesSubtractCreatedAt(updatedData);
    updatedData = mapKeysToShort(updatedData);
    const stringified = JSON.stringify(updatedData);
    logger.log("PMUser current size %s + persis length %s", getPMUserLength(request), stringified.length);
    request.setVariable(TransportVariables.VWRS_PERSIST, stringified);
};
const formatReqStatusResponse = (reqStatus) => {
    if (!reqStatus) {
        return;
    }
    let modifiedReqStatus = { ...reqStatus };
    // removing backoff_interval, dequeue_mode from reqStatus
    const { backoff_interval, dequeue_mode, ...remainingValues } = modifiedReqStatus;
    modifiedReqStatus = remainingValues;
    if (Connection.getInstance().statusConfigLimits.avgWaitingTime) {
        // remove avg_waiting_time from reqStatus
        const { avg_waiting_time, ...remainingValues } = modifiedReqStatus;
        modifiedReqStatus = remainingValues;
    }
    if (Connection.getInstance().statusConfigLimits.position) {
        // remove position from reqStatus
        const { position, ...remainingValues } = modifiedReqStatus;
        modifiedReqStatus = remainingValues;
    }
    if (Connection.getInstance().statusConfigLimits.qDepth) {
        // remove QDepth from reqStatus
        const { queue_depth, ...remainingValues } = modifiedReqStatus;
        modifiedReqStatus = remainingValues;
    }
    return modifiedReqStatus;
};
const isWaitingRoomPath = (request) => {
    const statusCode = request.getVariable(TransportVariables.STATUS_CODE);
    return [
        StatusCode.SUCCESS_HTTP_STATUS_LIVE,
        StatusCode.SUCCESS_ROUTE_WAITING_LIVE,
    ].includes(statusCode);
};
// Function to recursively map keys
const mapKeys = (obj, keyMap, reverse = false) => {
    // Check if obj is an object and not null
    if (obj === null || typeof obj !== "object") {
        return obj;
    }
    return Object.keys(obj).reduce((acc, key) => {
        const mappedKey = reverse ? keyMap[key] || key : keyMap[key] || key;
        acc[mappedKey] = mapKeys(obj[key], keyMap, reverse);
        return acc;
    }, {});
};
// Function to map long keys to short keys
const mapKeysToShort = (data) => {
    return mapKeys(data, keyMappings);
};
// Function to map short keys back to long keys
const mapKeysToLong = (data) => {
    const reversedMappings = Object.fromEntries(Object.entries(keyMappings).map(([k, v]) => [v, k]));
    return mapKeys(data, reversedMappings, true);
};
const getCookiePath = (waitingroom_url) => {
    const slashIndex = waitingroom_url.indexOf(EwPaths.ROOT);
    return slashIndex > -1 ? waitingroom_url.substring(slashIndex) : EwPaths.ROOT;
};
const updateTimesSubtractCreatedAt = (data) => {
    if (!data?.createdAt)
        return data;
    if (data?.meta?.requestDetails) {
        const { createdAt } = data;
        const details = data.meta.requestDetails;
        if (details.lastReqTime) {
            details.lastReqTime -= createdAt;
        }
        if (details.created_at) {
            details.created_at -= createdAt;
        }
        if (details.nextCallTime) {
            details.nextCallTime -= createdAt;
        }
    }
    return data;
};
const updateTimesAddCreatedAt = (data) => {
    if (!data?.createdAt)
        return data;
    if (data?.meta?.requestDetails) {
        const { createdAt } = data;
        const details = data.meta.requestDetails;
        if (details.lastReqTime) {
            details.lastReqTime += createdAt;
        }
        if (details.created_at) {
            details.created_at += createdAt;
        }
        if (details.nextCallTime) {
            details.nextCallTime += createdAt;
        }
    }
    return data;
};
const getPMUserLength = (request, withPersistSize = false) => {
    let size = 0;
    if (request.getVariable(TransportVariables.AVG_WAITING_TIME))
        size +=
            TransportVariables.AVG_WAITING_TIME.length +
                (request.getVariable(TransportVariables.AVG_WAITING_TIME)?.length || 0);
    if (request.getVariable(TransportVariables.FLOW))
        size +=
            TransportVariables.FLOW.length +
                (request.getVariable(TransportVariables.FLOW)?.length || 0);
    if (request.getVariable(TransportVariables.REQUEST_COUNT))
        size +=
            TransportVariables.REQUEST_COUNT.length +
                (request.getVariable(TransportVariables.REQUEST_COUNT)?.length || 0);
    if (request.getVariable(TransportVariables.STATUS_CODE))
        size +=
            TransportVariables.STATUS_CODE.length +
                (request.getVariable(TransportVariables.STATUS_CODE)?.length || 0);
    if (withPersistSize && request.getVariable(TransportVariables.VWRS_PERSIST))
        size +=
            TransportVariables.VWRS_PERSIST.length +
                (request.getVariable(TransportVariables.VWRS_PERSIST)?.length || 0);
    return size;
};
const generateRandomInteger = (min, max) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
};

const getAccessCookieMaxAge = (grantedAt, accessDuration, originAccessMode) => {
    const maxAge = originAccessMode === OriginAccessMode.ORIGIN_USAGE_TIME
        ? // maxAge is the remaining time from "gratedAt"
            accessDuration - VwrDurations.getTimeElapsedSec(grantedAt)
        : // maxAge is a new block of time equal to accessDuration
            accessDuration;
    return maxAge;
};
const checkCookieExpiration = (expireAt) => {
    return expireAt ? expireAt <= VwrDurations.currentTime : true;
};
// ------------------- digest helpers -------------------
const getFinalKeyedData = (data, key = false) => key ? `${data}.${Connection.getInstance().digestKey}` : data;
const createDigest = async (request, data, key = false) => {
    const finalData = getFinalKeyedData(data, key);
    const encoder = new TextEncoder();
    const buf = encoder.encode(finalData);
    let digested = await crypto.subtle.digest("SHA-256", buf).catch((e) => {
        logger.log("E:Digest creation failed");
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.ERROR_SECURITY_DIGEST_CREATE);
        throw e;
    });
    // Format the output into hex
    let walkable = Array.from(new Uint8Array(digested));
    let hex = walkable.map((b) => b.toString(16).padStart(2, "0")).join("");
    return hex;
};
const verifyDigest = async (request, digestReceived, data, key = false) => {
    const digest = await createDigest(request, data, key);
    return digestReceived === digest;
};
const createFingerprint = async (request, extraFingerPrint) => {
    const { device } = request;
    const fingerprint = await createDigest(request, JSON.stringify({ ...device, extraFingerPrint }));
    return fingerprint;
};
const verifyfingerprint = async (fingerprintReceived, request, extraFingerPrint) => {
    const fingerprint = await createFingerprint(request, extraFingerPrint);
    return fingerprintReceived === fingerprint;
};
// ------------------- encryption helpers -------------------
const stringToUint8Array = (data) => {
    const encoder = new TextEncoder();
    return encoder.encode(data);
};
const uint8ArrayToString = (data) => {
    const decoder = new TextDecoder();
    return decoder.decode(data);
};
const getImportedRawKey = async (request) => {
    const encryptionKey = Connection.getInstance().encryptionKey;
    const rawKey = stringToUint8Array(encryptionKey);
    const key = await crypto.subtle
        .importKey("raw", rawKey, { name: Encryption.ALGORITHM }, false, [
        "encrypt",
        "decrypt",
    ])
        .catch((e) => {
        logger.log("E:Getting imported raw key failed");
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.ERROR_SECURITY_ENCRYPTION_RAW_KEY);
        throw e;
    });
    return key;
};
const encrypt = async (request, data) => {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await getImportedRawKey(request);
    const encryptedData = await crypto.subtle
        .encrypt({ name: Encryption.ALGORITHM, iv: iv }, key, stringToUint8Array(data))
        .catch((e) => {
        logger.log("E:Encryption failed");
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.ERROR_SECURITY_COOKIE_ENCRYPTION);
        throw e;
    });
    const base = `${base64Encode(iv)}${Encryption.DELIMITER}${base64Encode(new Uint8Array(encryptedData))}`;
    return base;
};
const decrypt = async (request, data) => {
    const [ivStr, eDataStr] = data.split(Encryption.DELIMITER);
    const iv = base64.decode(ivStr, "Uint8Array");
    const eData = base64.decode(eDataStr, "Uint8Array");
    const key = await getImportedRawKey(request);
    const decryptedData = await crypto.subtle
        .decrypt({ name: Encryption.ALGORITHM, iv: iv }, key, eData)
        .catch((e) => {
        logger.log("E:Decryption failed");
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.ERROR_SECURITY_COOKIE_DECRYPTION);
        throw e;
    });
    return uint8ArrayToString(decryptedData);
};
function base64Encode(input) {
    const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let output = "";
    for (let i = 0; i < input.length; i += 3) {
        let byte1 = input[i];
        let byte2 = input[i + 1] ? input[i + 1] : 0;
        let byte3 = input[i + 2] ? input[i + 2] : 0;
        let encoded1 = byte1 >> 2;
        let encoded2 = ((byte1 & 3) << 4) | (byte2 >> 4);
        let encoded3 = ((byte2 & 15) << 2) | (byte3 >> 6);
        let encoded4 = byte3 & 63;
        // If the input length is not divisible by 3
        if (input[i + 1] === undefined) {
            encoded3 = 64;
            encoded4 = 64;
        }
        else if (input[i + 2] === undefined) {
            encoded4 = 64;
        }
        output += base64Chars[encoded1];
        output += base64Chars[encoded2];
        output += base64Chars[encoded3];
        output += base64Chars[encoded4];
    }
    return output;
}
// ------------------- encryption helpers -------------------

const getVersion = () => logger.log("VWRoomVersion %s", VWRoomVersion);
const gotoOrigin = async (request, requestOpts) => {
    logger.log("go to origin");
    const { meta: { requestDetails: { reqId }, waitingroomDetails: { waitingroom_key }, }, } = getPersistedData(request);
    persistTokenType(request, TokenType.ACCESS);
    if (isStatusPath(request)) {
        logger.log("moving request to status path");
        // waiting room UI should reload itself on the origin path
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.SUCCESS_HTTP_STATUS_LIVE);
        request.respondWith(HttpStatusCodes.REDIRECT, { [Headers.CONTENT_TYPE]: MimeTypes.JSON }, buildStatusBody(reqId, GoingTo.ORIGIN));
    }
    else {
        // as we are just doing for browsers push metrics only when actually going to origin
        notifyMetricServer(request, reqId, waitingroom_key);
        // NOOP - goes to origin
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.SUCCESS_ROUTE_ORIGIN_LIVE);
    }
};
const goToPreview = async (request, requestOpts) => {
    const waitingRoomPath = await getWaitingRoomPath(request, requestOpts);
    if (!waitingRoomPath) {
        logger.log("E:No waiting room path set for preview");
        return request.respondWith(HttpStatusCodes.NOT_FOUND, {
            [Headers.CONTENT_TYPE]: MimeTypes.HTML,
        }, "Waiting Room Not Found");
    }
    if (isStatusPath(request)) {
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.SUCCESS_HTTP_STATUS_PREVIEW);
        request.respondWith(HttpStatusCodes.OK, { [Headers.CONTENT_TYPE]: MimeTypes.JSON }, buildStatusBody(PreviewStatusResponse.REQ_ID, GoingTo.WAITING, PreviewStatusResponse.PREVIEW_DATA_OBJ));
    }
    else {
        const conditionalOrigin = VwrDefaults.WAITING_ROOM_ORIGIN;
        logger.log("Previewing Waiting room:", `${conditionalOrigin}${waitingRoomPath}`);
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.SUCCESS_ROUTE_WAITING_PREVIEW);
        request.route({
            origin: conditionalOrigin,
            path: waitingRoomPath,
        });
    }
};
const gotoWaitingRoom = async (request, requestOpts, reqStatus) => {
    logger.log("go to waiting room");
    const { meta: { requestDetails: { reqId }, waitingroomDetails: { waiting_room_path }, }, } = getPersistedData(request);
    persistTokenType(request, TokenType.SESSION);
    const isStatusRequest = isStatusPath(request);
    if (isStatusRequest) {
        const avgWaitingTime = reqStatus?.avg_waiting_time?.toString() ?? "";
        request.setVariable(TransportVariables.AVG_WAITING_TIME, avgWaitingTime);
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.SUCCESS_HTTP_STATUS_LIVE);
        request.respondWith(HttpStatusCodes.OK, { [Headers.CONTENT_TYPE]: MimeTypes.JSON }, buildStatusBody(reqId, GoingTo.WAITING, reqStatus));
    }
    else {
        const conditionalOrigin = VwrDefaults.WAITING_ROOM_ORIGIN;
        const reqWaitingRoomPath = requestOpts?.waitingRoomPath;
        logger.log("AltOrigin:", `${conditionalOrigin}${waiting_room_path}...req:${!!reqWaitingRoomPath}`);
        if (!waiting_room_path) {
            return request.respondWith(HttpStatusCodes.NOT_FOUND, {
                [Headers.CONTENT_TYPE]: MimeTypes.HTML,
            }, "Waiting Room Not Found");
        }
        request.addHeader(Headers.AUTH, Connection.getInstance().apiKey);
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.SUCCESS_ROUTE_WAITING_LIVE);
        request.route({
            origin: conditionalOrigin,
            path: waiting_room_path,
        });
    }
};
const verifyCookie = async (request, debugMode = false, extraFingerPrint = []) => {
    const response = { errors: [], cookieExists: false };
    const cookies = new Cookies(request.getHeader(Headers.COOKIE));
    const cookie = cookies.get(CookieIdentifier.SESSION);
    if (cookie) {
        response.cookieExists = true;
        const decryptedVal = await decrypt(request, cookie).catch(() => Encryption.DECRYPTION_FAILED);
        if (decryptedVal === Encryption.DECRYPTION_FAILED) {
            response.errors.push("Decryption Failed");
        }
        else {
            // decrypted value needs to be stored to be used everywhere else
            persistCookieData(request, debugMode, decryptedVal);
            const parsedCookie = JSON.parse(decryptedVal);
            if (parsedCookie) {
                const { digest, ...withoutDigest } = parsedCookie;
                // integrity check
                const isDigestValid = await verifyDigest(request, digest, JSON.stringify(withoutDigest), true);
                if (!isDigestValid) {
                    response.errors.push("Cookie integrity check failed");
                }
                // reuse check
                const { fingerprint } = withoutDigest;
                const isFingerprintValid = await verifyfingerprint(fingerprint, request, extraFingerPrint);
                if (!isFingerprintValid) {
                    response.errors.push("Cookie reuse check failed");
                }
                // check cookie expiry
                const { expireAt } = withoutDigest;
                const isCookieExpired = checkCookieExpiration(expireAt);
                if (isCookieExpired) {
                    response.errors.push("Cookie expired.");
                }
            }
        }
    }
    return response;
};
const calculateMockStatus = (currentPosition, rateLimit, requestTimeDiff) => {
    let totalDequeued = (requestTimeDiff * rateLimit) / 1000;
    totalDequeued = Math.ceil(totalDequeued * Connection.getInstance().backOffThreshold);
    const newPosition = Math.max(0, currentPosition - totalDequeued);
    const newWaitTime = Math.ceil(newPosition / rateLimit);
    return {
        newPosition,
        newWaitTime,
    };
};

const vwrhandler = async (request, requestOpts = {}) => {
    getVersion();
    const cookie = getPersistedData(request);
    if (cookie?.type === TokenType.ACCESS) {
        // persisted data from cookie will be enough
        await gotoOrigin(request);
    }
    else {
        let requestType;
        if (cookie?.type === TokenType.SESSION) {
            logger.log("session cookie found");
            requestType = RequestType.EXISTING_REQUEST;
        }
        else {
            logger.log("session cookie missing");
            if (isStatusPath(request)) {
                return request.respondWith(HttpStatusCodes.BAD_REQUEST, {}, "Status cannot be without token");
            }
            requestType = RequestType.NEW_REQUEST;
        }
        logger.log(`ReqType:${requestType}`);
        requestType === RequestType.NEW_REQUEST
            ? await newRequestHandler(request, requestOpts)
            : await existingRequestHandler(request, requestOpts);
    }
};
const newRequestHandler = async (request, requestOpts) => {
    const reqId = getUUID();
    // timestamp for when the cookie is created
    const cookieCreatedAt = VwrDurations.currentTime;
    const { meta: { waitingroomDetails: { is_queue_enabled, waitingroom_key, dequeue_mode }, requestDetails: { priority }, }, } = getPersistedData(request);
    logger.log(`Q is enabled ${is_queue_enabled}`);
    if (is_queue_enabled) {
        logger.log("Q is enabled");
        const { sid, created_at, backoff_interval, position, rate_limit, queue_depth, waiting_room_interval, } = await pushRequestToQueue(request, RequestType.NEW_REQUEST, reqId, waitingroom_key, priority).then((res) => res.json());
        logger.log("request pushed to Q", waitingroom_key, sid, created_at);
        // If we send this user to the waiting room,
        // the very next status request they make
        // will enable access to the origin.
        // While logically consistent, UX-wise this may look like a bug.
        // So we address this corner case by
        // just sending this request straight to the origin.
        const is_access = (position < rate_limit && dequeue_mode != DequeueMode.OFF);
        if (is_access) {
            persistData(request, {
                meta: {
                    requestDetails: {
                        reqId,
                        priority,
                        lastReqTime: cookieCreatedAt,
                        nextCallTime: backoff_interval * 1000 + cookieCreatedAt,
                        curPos: position,
                        rLimit: rate_limit,
                        qDepth: queue_depth,
                        statInt: waiting_room_interval,
                    },
                },
                createdAt: cookieCreatedAt,
            });
            await gotoOrigin(request);
        }
        else {
            persistData(request, {
                meta: {
                    requestDetails: {
                        reqId,
                        sid,
                        created_at,
                        priority,
                        lastReqTime: cookieCreatedAt,
                        nextCallTime: backoff_interval * 1000 + cookieCreatedAt,
                        curPos: position,
                        rLimit: rate_limit,
                        qDepth: queue_depth,
                        statInt: waiting_room_interval,
                    },
                },
                createdAt: cookieCreatedAt,
            });
            await gotoWaitingRoom(request, requestOpts);
        }
    }
    else {
        persistData(request, {
            meta: {
                requestDetails: { reqId, priority },
            },
            createdAt: cookieCreatedAt,
        });
        await gotoOrigin(request);
    }
};
const existingRequestHandler = async (request, requestOpts) => {
    const persistedData = getPersistedData(request);
    const reqId = persistedData?.meta?.requestDetails?.reqId;
    const sid = persistedData?.meta?.requestDetails?.sid;
    const waitingroom_key = persistedData?.meta?.waitingroomDetails?.waitingroom_key;
    const created_at = persistedData?.meta?.requestDetails?.created_at;
    const priority = persistedData?.meta?.requestDetails?.priority;
    const currentPosition = persistedData?.meta?.requestDetails?.curPos;
    const lastRequestTime = persistedData?.meta?.requestDetails?.lastReqTime;
    const nextStatusCallTime = persistedData?.meta?.requestDetails?.nextCallTime;
    const currentRequestTime = VwrDurations.currentTime;
    const queueDepth = persistedData?.meta?.requestDetails?.qDepth;
    const statusInterval = persistedData?.meta?.requestDetails?.statInt;
    const rateLimit = persistedData?.meta?.requestDetails?.rLimit;
    const delayTime = persistedData?.meta?.requestDetails?.delayTime;
    let reqStatusInQ;
    let requestDetails = {
        sid,
        created_at,
        reqId,
        priority,
        lastReqTime: currentRequestTime,
        qDepth: queueDepth,
        statInt: statusInterval,
        rLimit: rateLimit,
    };
    if (nextStatusCallTime && nextStatusCallTime > currentRequestTime) {
        // making mock response and sending response;
        const { newPosition, newWaitTime } = calculateMockStatus(currentPosition, rateLimit, currentRequestTime - lastRequestTime);
        reqStatusInQ = {
            avg_waiting_time: newWaitTime,
            position: newPosition,
            queue_depth: queueDepth < newPosition ? newPosition : queueDepth,
            waiting_room_interval: statusInterval,
            backoff_interval: 0,
            rate_limit: rateLimit,
            dequeue_mode: DequeueMode.ON, // Edgeworker don't know backend status assuming backend is dequeing until next call
        };
        // update current position in cookie and last request time
        requestDetails = {
            ...requestDetails,
            curPos: newPosition,
        };
        // checking edge case where queue depth is less than current position
        if (newPosition === 0 || queueDepth === 0) {
            logger.log("Fetching actual status call due", queueDepth, newPosition);
            reqStatusInQ = await getQueueStatusForRequest(request, reqId, waitingroom_key, sid, created_at, priority).then((res) => res.json());
            requestDetails.curPos = reqStatusInQ.position;
        }
    }
    else {
        reqStatusInQ = await getQueueStatusForRequest(request, reqId, waitingroom_key, sid, created_at, priority).then((res) => res.json());
        requestDetails = {
            ...requestDetails,
            qDepth: reqStatusInQ.queue_depth,
            statInt: reqStatusInQ.waiting_room_interval,
            rLimit: reqStatusInQ.rate_limit,
        };
        // logic for dequeue on and off
        if (reqStatusInQ.dequeue_mode === DequeueMode.OFF) {
            logger.log("Dequeue mode is disabled %s", reqStatusInQ.dequeue_mode);
            // When dequeue is disable backend should send backoff_interval zero
            requestDetails = {
                ...requestDetails,
                curPos: currentPosition,
                nextCallTime: currentRequestTime,
                delayTime: delayTime
                    ? delayTime + generateRandomInteger(20, 25)
                    : reqStatusInQ.avg_waiting_time,
            };
            // Increasing wait time as dequeue is disabled
            reqStatusInQ.avg_waiting_time = requestDetails.delayTime; // calculate mock wait time by increasing 20 to 30 seconds
            reqStatusInQ.position = currentPosition;
        }
        else {
            // update current position in cookie, backoff_interval
            const isEWInSync = currentPosition > reqStatusInQ.position;
            logger.log("Dequeue mode is enabled %s isEWInSync %s", reqStatusInQ.dequeue_mode, isEWInSync);
            requestDetails = {
                ...requestDetails,
                delayTime: undefined,
                curPos: isEWInSync ? reqStatusInQ.position : currentPosition,
                nextCallTime: isEWInSync
                    ? reqStatusInQ.backoff_interval * 1000 +
                        currentRequestTime
                    : currentRequestTime,
            };
            if (!isEWInSync) {
                // Disabling backoff until server and EW are not in Sync.
                reqStatusInQ.backoff_interval = 0;
                reqStatusInQ.position = currentPosition;
            }
        }
        // when no backoff interval is reached we are sending all call to server
        if (Connection.getInstance().noBackOffThreshold >=
            reqStatusInQ.backoff_interval) {
            logger.log("backoff is disabled as time reached");
            delete requestDetails.nextCallTime;
        }
    }
    persistData(request, {
        meta: {
            requestDetails,
        },
    });
    if (reqStatusInQ.position === 0) {
        // persisted data from cookie will be enough
        /**
         * when going from waiting_room to origin
         * a "new" access cookie should be created
         * with the same data as existing, other than the "createdAt" field
         * as a new custom TTL is given for access cookie
         */
        persistData(request, {
            createdAt: VwrDurations.currentTime,
        });
        await gotoOrigin(request);
    }
    else {
        if (!isStatusPath(request)) {
            // non-status requests if come again are treated as duplicate
            await pushRequestToQueue(request, RequestType.EXISTING_REQUEST, reqId, waitingroom_key, priority);
        }
        // persisted data from cookie will be enough
        await gotoWaitingRoom(request, requestOpts, reqStatusInQ);
    }
};

const setGeneralAttributes = (request, waitingroom_url = EwPaths.ROOT) => {
    return {
        name: CookieIdentifier.SESSION,
        waitingroom: request.host,
        sameSite: "Strict",
        httpOnly: true,
        secure: true,
        // the cookie should be set on the 'waitingroom_url'
        // so that its sub-paths also share it
        path: waitingroom_url,
    };
};
const getResponseConfig = (request) => {
    const flow = request.getVariable(TransportVariables.FLOW);
    const headers = [];
    if (flow === Flow.NO_WAITING_ROOM) {
        headers.push({ [Headers.NO_WAITING_ROOM]: "No Waiting Room Configured" });
        return { headers };
    }
    if (flow === Flow.INSECURE) {
        headers.push({ [Headers.INSECURE]: "Deemed Insecure" });
        return { headers };
    }
    const cookieBase = getPersistedData(request);
    if (!cookieBase) {
        headers.push({ [Headers.NO_TOKEN_FOUND]: "No Token Found" });
        return { headers };
    }
    return {
        cookieBase,
        headers,
    };
};
const getTTL = (request, cookieBase) => {
    let maxAge = 0;
    if (cookieBase?.type === TokenType.SESSION) {
        const avgWaitingTime = request.getVariable(TransportVariables.AVG_WAITING_TIME);
        maxAge = VwrDurations.getSessionMaxAgeSec(avgWaitingTime);
    }
    else if (cookieBase?.type === TokenType.ACCESS) {
        const accessDuration = cookieBase?.meta?.waitingroomDetails?.max_origin_usage_time ||
            VwrDurations.accessMaxAgeInSec;
        const createdAt = cookieBase.createdAt;
        if (typeof createdAt === "number") {
            const originAccessMode = Connection.getInstance().originAccessMode;
            logger.log(`Access Mode: ${originAccessMode}`);
            maxAge = getAccessCookieMaxAge(createdAt, accessDuration, originAccessMode);
        }
        else {
            logger.log("Access token should have 'createdAt'");
            request.setVariable(TransportVariables.STATUS_CODE, StatusCode.ERROR_SECURITY_COOKIE_CREATED_AT);
            throw new Error("No 'createdAt' found");
        }
    }
    else {
        logger.log("E:Neither access nor session token!");
        request.setVariable(TransportVariables.STATUS_CODE, StatusCode.ERROR_SECURITY_TOKEN_EXISTENCE);
        throw new Error("No token found");
    }
    const expireAt = VwrDurations.getCookieExpireAt(maxAge);
    return { maxAge, expireAt };
};
const getCookieSecurity = async (request, extraFingerPrint, cookieBase) => {
    const { expireAt, maxAge } = getTTL(request, cookieBase);
    const fingerprint = await createFingerprint(request, extraFingerPrint);
    const digest = await createDigest(request, JSON.stringify({ ...(cookieBase ?? {}), expireAt, fingerprint }), true);
    return {
        cookieSecurity: {
            expireAt,
            digest,
            fingerprint,
        },
        cookieProperties: {
            ...setGeneralAttributes(request, cookieBase?.meta?.waitingroomDetails?.waitingroom_url),
            maxAge,
        },
    };
};
const setHeaders = (response, headers) => {
    headers.forEach((headerObj) => {
        const [header, value] = Object.entries(headerObj)[0];
        response.addHeader(header, value);
    });
};

/**
 * Handles request and response flow of VWRS
 * including handling requests, managing responses, and managing cookies.
 *
 * @example
 * const config: IConnection = {
 *   vwrsHost: "example.com",
 *   apiKey: "your-api-key",
 *   vwrsMetricHost: "example.com",
 *   isFailOpen: false,
 *   digestKey:"YourVwrsDigestKey",
 *   encryptionKey: "YourVwrsEncryptionKey",
 *   originAccessMode: "ORIGIN_USAGE_TIME | ORIGIN_IDLE_TIME",
 *   retryLimit: 1,
 *   statusConfigLimits:{
 *     avgWaitingTime: true|false,
 *     qDepth: true|false,
 *     position: true|false,
 *   },
 *   requestTimeout: 4500
 * };
 * const client = new VirtualWaitingRoom(config);
 * client.handleVwrsRequest(request);
 */
class VirtualWaitingRoom {
    /**
     * Constructs a new instance of the Client class.
     * Initializes the connection with the given configuration or default configuration if not provided.
     * give values in statusConfigLimits as true to restrict them from the status call response.(by default all values are false)
     * @param {IConnection} [config={}] - The optional connection configuration object, containing the VWRS URL, API key, and VWRS Metric URL.
     * {
     *    apiKey: "YourAPIKey",
     *    vwrsMetricUrl: "YourVwrsMetricUrl",
     *    vwrsURL: "YourVwrsURL",
     *    isFailOpen:true | false <set it to 'true' to navigate to origin in case of failure>,
     *    digestKey:"YourVwrsDigestKey",
     *    encryptionKey: "YourVwrsEncryptionKey",
     *    originAccessMode: "ORIGIN_USAGE_TIME",
     *    retryLimit: 1
     *    statusConfigLimits:{
     *      avgWaitingTime:true|false,
     *      qDepth: true|false,
     *      position: true|false,
     *    }
     *  }
     */
    constructor(config) {
        Connection.createInstance(config);
    }
    /**
     * Handles the waiting room request. Should be called on the "onClientRequest" event of the edge worker
     *
     * @param {EW.IngressClientRequest} request - The incoming EW request object.
     * @param {IRequestOptions} requestOpts - Additional options to pass on a per request basis.
     */
    async handleVwrsRequest(request, requestOpts) {
        logger.log("handleVwrsRequest", request.path);
        try {
            request.setVariable(TransportVariables.REQUEST_COUNT, "0");
            //if its a "HTML preview req", just show the preview, no need for further processing
            if (isPreviewPath(request)) {
                await goToPreview(request, requestOpts);
                return { waitingRoom: false };
            }
            const { errors, cookieExists } = await verifyCookie(request, requestOpts?.debugMode, requestOpts?.extraFingerPrint);
            if (errors.length > 0) {
                request.setVariable(TransportVariables.FLOW, Flow.INSECURE);
                request.respondWith(HttpStatusCodes.BAD_REQUEST, {}, JSON.stringify(errors));
                return { waitingRoom: false };
            }
            let result = {};
            // if cookie are received for this path then it means we are on the correct path
            // as the "path" attribute of cookies is set
            if (!cookieExists) {
                const response = await getWaitingRoomDetails(request);
                const { status } = response;
                if (status === HttpStatusCodes.OK) {
                    result = await response.json();
                }
                else if (status === HttpStatusCodes.NOT_FOUND) {
                    logger.log("E:Waiting room not found");
                    request.setVariable(TransportVariables.FLOW, Flow.NO_WAITING_ROOM);
                }
            }
            if (cookieExists || Object.keys(result).length > 0) {
                if (Object.keys(result).length > 0) {
                    const { max_origin_usage_time, waiting_room_path: waitingRoomPath, is_queue_enabled, waitingroom_key, waitingroom_url, dequeue_mode, } = result;
                    const reqWaitingRoomPath = requestOpts?.waitingRoomPath;
                    const waiting_room_path = reqWaitingRoomPath ?? waitingRoomPath;
                    const cookiePath = getCookiePath(waitingroom_url);
                    persistData(request, {
                        meta: {
                            waitingroomDetails: {
                                max_origin_usage_time,
                                waiting_room_path,
                                is_queue_enabled,
                                waitingroom_key,
                                waitingroom_url: cookiePath,
                                dequeue_mode,
                            },
                            requestDetails: {
                                priority: requestOpts?.priority ?? VwrDefaults.PRIORITY,
                            },
                        },
                    });
                }
                request.setVariable(TransportVariables.FLOW, Flow.NORMAL);
                await vwrhandler(request, requestOpts);
            }
            return { waitingRoom: isWaitingRoomPath(request) };
        }
        catch (e) {
            await errorHandler(request, requestOpts, true, e);
            return { waitingRoom: false };
        }
    }
    /**
     * Handles the waiting room response and set the session and access cookies.
     *
     * @param {EW.EgressClientRequest} request - The incoming EW request object.
     * @param {EW.EgressClientResponse} response - The outgoing EW response object.
     * @param {Array<string>} extraFingerPrint - Additional fingerprint values.
     * @warning Do not use this method if you are overriding the cookies.
     * @warning Instead use processVwrsResponseAndGetCookies to get the cookies and set accordingly.
     */
    async handleVwrsResponse(request, response, requestOpts) {
        logger.log("on response");
        try {
            //if its a "HTML preview req", no need for further processing
            if (isPreviewPath(request)) {
                return { waitingRoom: false };
            }
            const flow = request.getVariable(TransportVariables.FLOW);
            logger.log(`ResFlow: ${flow}`);
            const { headers, cookieBase } = getResponseConfig(request);
            // only set the cookies if the waiting room config exists and there was no error while handling the ingress
            if (flow !== Flow.INGRESS_ERROR && flow !== Flow.NO_WAITING_ROOM) {
                const { cookieSecurity, cookieProperties } = await getCookieSecurity(request, requestOpts?.extraFingerPrint || [], cookieBase);
                const cookieValue = JSON.stringify({
                    ...cookieBase,
                    ...cookieSecurity,
                });
                const encryptedValue = await encrypt(request, cookieValue);
                const cookie = new SetCookie({
                    ...cookieProperties,
                    value: encryptedValue,
                });
                if (requestOpts?.debugMode === true) {
                    logger.log("Unencrypted Cookie: %s", cookieValue);
                    response.addHeader(Headers.X_VWRS_DEBUG, cookieValue);
                    const reqCount = request.getVariable(TransportVariables.REQUEST_COUNT);
                    response.addHeader(Headers.X_SUB_REQUEST_COUNT, reqCount);
                }
                response.addHeader(Headers.SET_COOKIE, cookie.toHeader());
                // disable any browser cache for response by VWRS
                // so that waiting room page to origin page is served properly
                response.addHeader(Headers.CACHE, CacheValues.NO_CACHE);
            }
            setHeaders(response, headers);
            return { waitingRoom: isWaitingRoomPath(request) };
        }
        catch (e) {
            await errorHandler(request, requestOpts, false, e);
            return { waitingRoom: false };
        }
    }
    /**
     * Updates the config for edge-worker to work upon.
     *
     * @param {IConnection} [config={}] - The connection configuration object, containing the VWRS URL, API key, and VWRS Metric URL.
     *  {
     *    apiKey: "YourAPIKey",
     *    vwrsMetricUrl: "YourVwrsMetricUrl",
     *    vwrsURL: "YourVwrsURL",
     *    digestKey: "YourVwrsDigestKey",
     *  }
     */
    updateConfig(config) {
        Connection.getInstance().updateConfig(config);
    }
}

export { VirtualWaitingRoom as default };
