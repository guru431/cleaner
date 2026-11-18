"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor() {
    this.dataset = {};
    this.listeners = {};
    this.classList = { remove() {} };
    this.messages = [];
  }
  addEventListener(name, fn) { (this.listeners[name] ??= []).push(fn); }
  dispatchEvent(event) { for (const fn of this.listeners[event.type] || []) fn(event); }
  append() {}
  setAttribute() {}
  after(message) { this.messages.push(message); }
  querySelector() { return new Element(); }
  closest(selector) { return selector === "form" ? this.form : null; }
}

function load({ manualCopy, manualSource, selection, fetch } = {}) {
  const fields = [new Element(), new Element()];
  for (const field of fields) {
    field.form = new Element();
    field.files = [];
    // Upload-preview behavior has its own coverage; record the event here.
    field.dispatchEvent = () => { field.changes = (field.changes || 0) + 1; };
  }
  const stream = new Element();
  stream.dataset.stream = "/events";
  const find = new Element();
  const found = new Element();
  const rows = [
    { cells: [{ textContent: "short" }, { textContent: "row" }] },
    { cells: [{ textContent: "<TERM_1>" }, {}, { textContent: "needle" }] },
  ];
  const doc = new Element();
  doc.body = new Element();
  doc.documentElement = new Element();
  doc.createElement = () => new Element();
  doc.getElementById = (id) => id === "manual-text" ? manualSource : null;
  doc.getSelection = () => selection;
  doc.querySelector = (selector) => ({
    "[data-entities-found]": found, "[data-manual-receipt]": manualCopy,
  })[selector] || null;
  doc.querySelectorAll = (selector) => ({
    "[data-upload-batch]": fields, "[data-stream]": [stream],
    "#entities-find": [find], "#entities-table tbody tr": rows,
  })[selector] || [];
  class Source extends Element {
    static CLOSED = 2;
    constructor() { super(); Source.current = this; this.readyState = 0; }
    close() { this.closed = true; }
  }
  class Transfer {
    constructor() { this.files = []; this.items = { add: (file) => this.files.push(file) }; }
  }
  class File {
    constructor(parts, name, options) { this.name = name; this.type = options.type; }
  }
  const context = {
    document: doc, window: new Element(), EventSource: Source, DataTransfer: Transfer, File,
    history: { state: {} },
    URLSearchParams, fetch,
    Event: class { constructor(type) { this.type = type; } },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../cleaner/web/static/app.js"), "utf8"), context);
  return { fields, stream, source: Source.current, find, found, rows, doc };
}

const page = load();
assert.equal(page.doc.listeners.paste.length, 1);
const paste = (target) => {
  let prevented = false;
  page.doc.dispatchEvent({ type: "paste", target, clipboardData: {
    types: ["Files"], files: [{ type: "image/png" }],
  }, preventDefault() { prevented = true; } });
  return prevented;
};
assert.equal(paste(page.fields[1]), true);
assert.equal(page.fields[0].files.length, 0);
assert.equal(page.fields[1].files.length, 1);
assert.equal(page.fields[1].changes, 1);
assert.equal(paste(new Element()), false);

page.source.onerror();
page.source.onerror();
assert.equal(page.source.closed, undefined);
page.source.onerror();
assert.equal(page.source.closed, true);
assert.equal(page.stream.messages.length, 1);
const permanent = load();
permanent.source.readyState = 2;
permanent.source.onerror();
assert.equal(permanent.source.closed, true);

page.find.value = "needle";
page.find.dispatchEvent({ type: "input" });
assert.equal(page.rows[1].hidden, false);
assert.match(page.found.textContent, /1 из 1/);

const manualCopy = new Element();
manualCopy.dataset = { copy: "manual-text", manualCopied: "/chats/chat/manual/copied", manualCsrf: "csrf", manualReceipt: "sealed" };
const manualSource = new Element();
manualSource.textContent = "Cleaned dialogue";
manualSource.contains = () => true;
const calls = [];
const manualPage = load({ manualCopy, manualSource, selection: { toString: () => "Cleaned dialogue" },
  fetch: async (url, options) => { calls.push([url, options.method, options.body.toString()]); return { ok: true }; } });
manualPage.doc.dispatchEvent({ type: "copy" });
assert.deepEqual(calls, [["/chats/chat/manual/copied", "POST", "csrf=csrf&receipt=sealed"]]);

console.log("Browser event regressions passed");
