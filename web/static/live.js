"use strict";

(() => {
  const POLL_INTERVAL_MS = 5000;
  const HIDDEN_INTERVAL_MS = 30000;
  const REQUEST_TIMEOUT_MS = 4000;
  const SSE_FAILURES_BEFORE_FALLBACK = 3;
  const roomState = new Map();
  let appliedEventId = 0;

  function element(tagName, className, text) {
    const node = document.createElement(tagName);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function integer(value) {
    const selected = Number(value);
    return Number.isSafeInteger(selected) && selected >= 0 ? selected : 0;
  }

  function setText(selector, value) {
    const node = document.querySelector(selector);
    if (node) node.textContent = String(value);
  }

  function updateRatio(name, value, total) {
    const node = document.querySelector(`[data-live-ratio="${name}"]`);
    if (!node) return;
    node.textContent = total ? `${((value / total) * 100).toFixed(1)}% of observations` : "No observations yet";
  }

  function updateMetrics(summary) {
    const observations = integer(summary.observations);
    const didPresent = integer(summary.identity?.did_present);
    const unsigned = integer(summary.identity?.unsigned);
    setText('[data-live-metric="observations"]', observations);
    setText('[data-live-metric="did-present"]', didPresent);
    setText('[data-live-metric="unsigned"]', unsigned);
    setText('[data-live-metric="high-risk"]', integer(summary.severity?.high));
    setText('[data-live-metric="rooms"]', Array.isArray(summary.monitored_rooms) ? summary.monitored_rooms.length : 0);
    updateRatio("did-present", didPresent, observations);
    updateRatio("unsigned", unsigned, observations);
  }

  function identityDetails(event) {
    if (event.signed_identity_present) return ["identity-signed", "Signed metadata"];
    if (typeof event.did === "string" && event.did.startsWith("did:key:")) {
      return ["identity-did", "DID present"];
    }
    return ["identity-unsigned", "Unsigned"];
  }

  function createEventRow(event) {
    const row = element("tr");
    const eventId = integer(event.id);
    row.dataset.eventId = String(eventId);

    const timeCell = element("td");
    const staticFrontend = document.body.hasAttribute("data-static-frontend");
    const time = element(staticFrontend ? "span" : "a", "event-time", event.timestamp || "Not available");
    if (!staticFrontend) time.href = `/events/${eventId}`;
    timeCell.append(time);
    row.append(timeCell);

    const roomCell = element("td");
    roomCell.append(element("span", "room-badge", `#${event.room || "unknown"}`));
    row.append(roomCell);

    const sequenceCell = element("td");
    sequenceCell.append(element("code", "sequence", integer(event.sequence)));
    row.append(sequenceCell);

    const senderCell = element("td", "sender");
    senderCell.append(element("strong", "", event.sender || "Unknown"));
    if (event.did) {
      const did = element("span", "did-preview", event.did);
      did.title = String(event.did);
      senderCell.append(did);
    }
    row.append(senderCell);

    const identityCell = element("td");
    const [identityClass, identityLabel] = identityDetails(event);
    const identity = element("span", `identity ${identityClass}`);
    identity.append(element("span"), document.createTextNode(identityLabel));
    identityCell.append(identity);
    row.append(identityCell);

    const flagsCell = element("td", "flags-cell");
    const flags = Array.isArray(event.flags) ? event.flags : [];
    if (flags.length) {
      flags.forEach((flag) => flagsCell.append(element("span", "flag", flag)));
    } else {
      flagsCell.append(element("span", "muted", "—"));
    }
    row.append(flagsCell);

    const selectedSeverity = String(event.severity || "NONE").toUpperCase();
    const severityName = ["HIGH", "MEDIUM", "LOW", "INFO", "NONE"].includes(selectedSeverity) ? selectedSeverity : "NONE";
    const severityCell = element("td");
    const severity = element("span", `severity severity-${severityName.toLowerCase()}`);
    severity.append(element("span"), document.createTextNode(severityName));
    severityCell.append(severity);
    row.append(severityCell);
    return row;
  }

  function createEventTable() {
    const wrap = element("div", "table-wrap");
    const table = element("table", "events-table");
    const head = element("thead");
    const headingRow = element("tr");
    ["Time", "Room", "Sequence", "Sender", "Identity status", "Flags", "Severity"].forEach((label) => {
      headingRow.append(element("th", "", label));
    });
    head.append(headingRow);
    table.append(head, element("tbody"));
    wrap.append(table);
    return wrap;
  }

  function createEventEmptyState() {
    const empty = element("div", "empty-state");
    const icon = element("span", "", "◇");
    icon.setAttribute("aria-hidden", "true");
    empty.append(
      icon,
      element("h3", "", "No matching observations"),
      element("p", "", "Watchtower will display metadata after a configured-room observation matches this view."),
    );
    return empty;
  }

  function updateEvents(events) {
    const container = document.querySelector("[data-live-event-container]");
    if (!container || !Array.isArray(events)) return;
    if (!events.length) {
      if (!container.querySelector(".empty-state")) container.replaceChildren(createEventEmptyState());
      return;
    }

    let table = container.querySelector("table");
    if (!table) {
      container.replaceChildren(createEventTable());
      table = container.querySelector("table");
    }
    const body = table.querySelector("tbody");
    const existing = new Map(
      Array.from(body.querySelectorAll("[data-event-id]"), (row) => [row.dataset.eventId, row]),
    );
    const retained = new Set();
    events.forEach((event) => {
      const id = String(integer(event.id));
      const row = existing.get(id) || createEventRow(event);
      retained.add(id);
      body.append(row);
    });
    existing.forEach((row, id) => {
      if (!retained.has(id)) row.remove();
    });
  }

  function updateChartList(container, points) {
    if (!container) return;
    const list = container.querySelector(".chart-data");
    if (!list) return;
    list.replaceChildren();
    points.forEach((point) => {
      const item = element("li", "", `${point.label}: ${integer(point.value)}`);
      item.dataset.label = point.label;
      item.dataset.value = String(integer(point.value));
      list.append(item);
    });
  }

  function updateCharts(summary) {
    const severity = ["high", "medium", "low", "info", "none"].map((name) => ({
      label: name.toUpperCase(),
      value: summary.severity?.[name],
    }));
    updateChartList(document.querySelector('[data-live-chart="severity"]'), severity);

    const region = document.querySelector('[data-live-chart-region="rooms"]');
    const rooms = Array.isArray(summary.top_flagged_rooms) ? summary.top_flagged_rooms : [];
    if (region && rooms.length) {
      let chart = region.querySelector('[data-live-chart="rooms"]');
      if (!chart) {
        chart = element("div", "chart-shell");
        chart.dataset.chart = "bars";
        chart.dataset.liveChart = "rooms";
        chart.dataset.label = "Rooms with the most flagged events";
        chart.append(element("canvas"), element("ul", "chart-data"));
        region.replaceChildren(chart);
      }
      updateChartList(chart, rooms.map((room) => ({ label: `#${room.room}`, value: room.events })));
    } else if (region) {
      const empty = element("div", "empty-state compact");
      const icon = element("span", "", "◇");
      icon.setAttribute("aria-hidden", "true");
      empty.append(icon, element("p", "", "No flagged room activity in this period."));
      region.replaceChildren(empty);
    }
    if (typeof window.renderCharts === "function") window.renderCharts();
  }

  function createRoomCard(room) {
    const card = element("article", "panel room-card");
    card.dataset.roomName = String(room.room || "");
    const head = element("div", "room-card-head");
    const title = element("div");
    title.append(
      element("span", "room-badge", `#${room.room || "unknown"}`),
      element("h2", "", `${integer(room.observations)} observations`),
    );
    const highest = integer(room.severity?.high) ? "high" : (integer(room.severity?.medium) ? "medium" : "none");
    const flagged = element("span", `severity severity-${highest}`);
    flagged.append(element("span"), document.createTextNode(`${integer(room.flagged_events)} flagged`));
    head.append(title, flagged);

    const details = element("dl");
    const sequence = element("div");
    sequence.append(element("dt", "", "Last sequence"), element("dd", "", room.last_sequence ?? "N/A"));
    const lastSeen = element("div");
    lastSeen.append(element("dt", "", "Last seen"), element("dd", "", room.last_seen || "Not available"));
    details.append(sequence, lastSeen);

    const strip = element("div", "severity-strip");
    strip.setAttribute("aria-label", "Severity counts");
    ["high", "medium", "low", "info", "none"].forEach((name) => {
      const item = element("span");
      item.append(element("i", `dot ${name}`), document.createTextNode(`${name[0].toUpperCase()}${name.slice(1)} `), element("strong", "", integer(room.severity?.[name])));
      strip.append(item);
    });

    const link = element("a", "text-link");
    link.href = `/events?room=${encodeURIComponent(String(room.room || ""))}`;
    link.append(document.createTextNode("View room events "), element("span", "", "→"));
    link.lastElementChild.setAttribute("aria-hidden", "true");
    card.append(head, details, strip, link);
    return card;
  }

  function createRoomEmptyState() {
    const empty = element("div", "panel empty-state");
    const icon = element("span", "", "◇");
    icon.setAttribute("aria-hidden", "true");
    empty.append(icon, element("h2", "", "No observed rooms yet"), element("p", "", "Room cards will appear after successful configured-room reads."));
    return empty;
  }

  function updateRooms(rooms) {
    const region = document.querySelector("[data-live-room-region]");
    if (!region || !Array.isArray(rooms)) return;
    roomState.clear();
    rooms.forEach((room) => roomState.set(String(room.room || ""), room));
    setText("[data-live-room-count]", rooms.length);
    if (!rooms.length) {
      if (!region.querySelector(".empty-state")) region.replaceChildren(createRoomEmptyState());
      return;
    }
    let grid = region.querySelector(".room-card-grid");
    if (!grid) {
      grid = element("section", "room-card-grid");
      region.replaceChildren(grid);
    }
    const existing = new Map(
      Array.from(grid.querySelectorAll("[data-room-name]"), (card) => [card.dataset.roomName, card]),
    );
    const retained = new Set();
    rooms.forEach((room) => {
      const name = String(room.room || "");
      const replacement = createRoomCard(room);
      const current = existing.get(name);
      if (current) current.replaceWith(replacement);
      grid.append(replacement);
      retained.add(name);
    });
    existing.forEach((card, name) => {
      if (!retained.has(name) && card.isConnected) card.remove();
    });
  }

  function eventApiUrl(limit) {
    const query = new URLSearchParams({ limit: String(limit) });
    const current = new URLSearchParams(window.location.search);
    ["room", "severity", "flag"].forEach((name) => {
      const value = current.get(name);
      if (value) query.set(name, value);
    });
    return `/api/v1/events?${query.toString()}`;
  }

  function observationMatchesFilters(observation) {
    const query = new URLSearchParams(window.location.search);
    const room = query.get("room");
    const severity = query.get("severity");
    const flag = query.get("flag");
    return (!room || observation.room === room)
      && (!severity || String(observation.severity).toUpperCase() === severity.toUpperCase())
      && (!flag || (Array.isArray(observation.flags) && observation.flags.includes(flag)));
  }

  function prependObservation(observation) {
    const container = document.querySelector("[data-live-event-container]");
    if (!container || !observationMatchesFilters(observation)) return;
    let table = container.querySelector("table");
    if (!table) {
      container.replaceChildren(createEventTable());
      table = container.querySelector("table");
    }
    const body = table.querySelector("tbody");
    const id = String(integer(observation.id));
    if (body.querySelector(`[data-event-id="${id}"]`)) return;
    body.prepend(createEventRow(observation));
    const limit = integer(document.querySelector("[data-live-event-region]")?.dataset.liveEventLimit) || 20;
    Array.from(body.children).slice(limit).forEach((row) => row.remove());
  }

  function incrementMetric(name) {
    const node = document.querySelector(`[data-live-metric="${name}"]`);
    if (!node) return;
    node.textContent = String(integer(node.textContent) + 1);
  }

  function incrementObservation(observation) {
    const eventId = integer(observation.id);
    if (eventId <= appliedEventId) return;
    appliedEventId = eventId;
    incrementMetric("observations");
    if (typeof observation.did === "string" && observation.did.startsWith("did:key:")) incrementMetric("did-present");
    if (!observation.signed_identity_present) incrementMetric("unsigned");
    if (String(observation.severity).toUpperCase() === "HIGH") incrementMetric("high-risk");

    const severityName = String(observation.severity || "NONE").toUpperCase();
    const severityPoint = document.querySelector(`[data-live-chart="severity"] [data-label="${severityName}"]`);
    if (severityPoint) {
      severityPoint.dataset.value = String(integer(severityPoint.dataset.value) + 1);
      severityPoint.textContent = `${severityName}: ${severityPoint.dataset.value}`;
      if (typeof window.renderCharts === "function") window.renderCharts();
    }

    const roomName = String(observation.room || "");
    const current = roomState.get(roomName);
    if (current) {
      const updated = {
        ...current,
        observations: integer(current.observations) + 1,
        last_sequence: integer(observation.sequence),
        last_seen: observation.timestamp,
        severity: { ...current.severity },
      };
      const level = String(observation.severity || "NONE").toLowerCase();
      updated.severity[level] = integer(updated.severity[level]) + 1;
      const riskFlags = ["UNSIGNED_PRIVILEGED_NAME", "POTENTIAL_TECHNOCORE_WRITE_URL", "SUSPICIOUS_COMBINATION"];
      if (Array.isArray(observation.flags) && observation.flags.some((flag) => riskFlags.includes(flag))) {
        updated.flagged_events = integer(current.flagged_events) + 1;
      }
      roomState.set(roomName, updated);
      updateRooms(Array.from(roomState.values()).sort((left, right) => String(left.room).localeCompare(String(right.room))));
    }
  }

  function syncEventFilters() {
    if (!document.querySelector("[data-live-events]")) return;
    const query = new URLSearchParams(window.location.search);
    ["room", "severity", "flag"].forEach((name) => {
      const select = document.querySelector(`select[name="${name}"]`);
      const value = query.get(name);
      if (select && value && Array.from(select.options).some((option) => option.value === value)) {
        select.value = value;
      }
    });
  }

  async function fetchJson(url, signal) {
    const response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
    if (!response.ok) throw new Error(`Read-only API returned ${response.status}`);
    return response.json();
  }

  async function fetchAll(requests) {
    const results = await Promise.allSettled(requests);
    const failed = results.find((result) => result.status === "rejected");
    if (failed) throw failed.reason;
    return results.map((result) => result.value);
  }

  function liveRequest() {
    const dashboard = document.querySelector("[data-live-dashboard]");
    if (dashboard) {
      return async (signal) => {
        const [summary, events, rooms] = await fetchAll([
          fetchJson("/api/v1/summary?hours=24", signal),
          fetchJson("/api/v1/events?limit=20", signal),
          fetchJson("/api/v1/rooms", signal),
        ]);
        updateMetrics(summary);
        updateEvents(events.events);
        updateRooms(rooms.rooms);
        updateCharts(summary);
      };
    }
    if (document.querySelector("[data-live-events]") && !new URLSearchParams(window.location.search).has("before_id")) {
      const limit = integer(document.querySelector("[data-live-event-region]")?.dataset.liveEventLimit) || 50;
      return async (signal) => updateEvents((await fetchJson(eventApiUrl(limit), signal)).events);
    }
    if (document.querySelector("[data-live-rooms]")) {
      return async (signal) => updateRooms((await fetchJson("/api/v1/rooms", signal)).rooms);
    }
    return null;
  }

  class LivePoller {
    constructor(request) {
      this.request = request;
      this.running = false;
      this.failures = 0;
      this.timer = null;
      this.controller = null;
      this.active = false;
      this.visibilityChanged = this.visibilityChanged.bind(this);
    }

    start() {
      if (this.active) return;
      this.active = true;
      document.addEventListener("visibilitychange", this.visibilityChanged);
      this.refresh();
    }

    stop() {
      if (!this.active) return;
      this.active = false;
      window.clearTimeout(this.timer);
      if (this.controller) this.controller.abort();
      document.removeEventListener("visibilitychange", this.visibilityChanged);
    }

    schedule(delay = this.nextDelay()) {
      if (!this.active) return;
      window.clearTimeout(this.timer);
      this.timer = window.setTimeout(() => this.refresh(), delay);
    }

    nextDelay() {
      if (document.visibilityState === "hidden") return HIDDEN_INTERVAL_MS;
      return Math.min(HIDDEN_INTERVAL_MS, POLL_INTERVAL_MS * (2 ** Math.min(this.failures, 3)));
    }

    async refresh() {
      if (this.running) {
        this.schedule();
        return;
      }
      this.running = true;
      this.controller = new AbortController();
      const timeout = window.setTimeout(() => this.controller.abort(), REQUEST_TIMEOUT_MS);
      try {
        await this.request(this.controller.signal);
        this.failures = 0;
        setConnectionStatus("fallback");
      } catch (_) {
        this.failures += 1;
        if (this.active) setConnectionStatus("reconnecting");
      } finally {
        window.clearTimeout(timeout);
        this.controller = null;
        this.running = false;
        this.schedule();
      }
    }

    visibilityChanged() {
      window.clearTimeout(this.timer);
      if (document.visibilityState === "visible") {
        if (this.running) this.schedule(POLL_INTERVAL_MS);
        else this.refresh();
      } else {
        this.schedule(HIDDEN_INTERVAL_MS);
      }
    }

  }

  let lastObservationAt = null;

  function setConnectionStatus(mode) {
    const labels = {
      streaming: " LIVE",
      fallback: " Live fallback",
      reconnecting: " Reconnecting…",
    };
    document.querySelectorAll("[data-live-status]").forEach((status) => {
      status.classList.remove("pending");
      status.classList.toggle("reconnecting", mode === "reconnecting");
      status.classList.toggle("fallback", mode === "fallback");
      const label = status.querySelector(".live-label");
      if (label) label.lastChild.textContent = labels[mode];
    });
    if (mode === "streaming" && lastObservationAt === null) {
      setText("[data-live-updated]", "Streaming");
    }
  }

  function updateObservationAge() {
    if (lastObservationAt === null) return;
    const seconds = Math.max(0, (Date.now() - lastObservationAt) / 1000);
    const label = seconds < 10 ? seconds.toFixed(1) : String(Math.floor(seconds));
    setText("[data-live-updated]", `Last event: ${label}s ago`);
  }

  class LiveController {
    constructor(request) {
      this.poller = new LivePoller(request);
      this.source = null;
      this.failures = 0;
    }

    start() {
      window.setInterval(updateObservationAge, 250);
      if (typeof window.EventSource !== "function") {
        this.poller.start();
        return;
      }
      const streamUrl = document.body.dataset.streamUrl || "/api/v1/stream";
      this.source = new EventSource(streamUrl);
      this.source.onopen = () => {
        this.failures = 0;
        this.poller.stop();
        setConnectionStatus("streaming");
      };
      this.source.onerror = () => {
        this.failures += 1;
        setConnectionStatus("reconnecting");
        if (this.failures >= SSE_FAILURES_BEFORE_FALLBACK) this.poller.start();
      };
      this.source.addEventListener("observation", (message) => {
        const observation = parseEventData(message);
        if (!observation) return;
        prependObservation(observation);
        incrementObservation(observation);
        lastObservationAt = Date.now();
        updateObservationAge();
      });
      this.source.addEventListener("summary", (message) => {
        const summary = parseEventData(message);
        if (!summary) return;
        appliedEventId = Math.max(appliedEventId, integer(summary.stream_through_event_id));
        updateMetrics(summary);
        updateCharts(summary);
      });
      this.source.addEventListener("room_update", (message) => {
        const update = parseEventData(message);
        if (update && Array.isArray(update.rooms)) updateRooms(update.rooms);
      });
    }
  }

  function parseEventData(message) {
    try {
      const value = JSON.parse(message.data);
      return value && typeof value === "object" ? value : null;
    } catch (_) {
      return null;
    }
  }

  syncEventFilters();
  const request = liveRequest();
  if (request) new LiveController(request).start();

  window.WatchtowerLive = Object.freeze({
    POLL_INTERVAL_MS,
    HIDDEN_INTERVAL_MS,
    updateEvents,
    updateRooms,
    prependObservation,
  });
})();
