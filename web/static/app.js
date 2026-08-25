"use strict";

const palette = {
  grid: "#263149",
  text: "#8994aa",
  blue: "#6f8cff",
  violet: "#9b7cff",
  green: "#43d6a1",
  amber: "#eab65a",
  red: "#f06b78",
};

function chartPoints(container) {
  return Array.from(container.querySelectorAll("[data-value]"), (item) => ({
    label: item.dataset.label || "",
    value: Number(item.dataset.value || 0),
  }));
}

function prepareCanvas(container) {
  const canvas = container.querySelector("canvas");
  const width = Math.max(280, container.clientWidth);
  const height = 230;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  return { context, width, height };
}

function drawLine(container, points) {
  const { context, width, height } = prepareCanvas(container);
  const left = 42;
  const right = 16;
  const top = 18;
  const bottom = 30;
  const innerWidth = width - left - right;
  const innerHeight = height - top - bottom;
  const max = Math.max(1, ...points.map((point) => point.value));

  context.strokeStyle = palette.grid;
  context.fillStyle = palette.text;
  context.font = "11px ui-sans-serif, system-ui";
  context.lineWidth = 1;
  for (let index = 0; index <= 4; index += 1) {
    const y = top + (innerHeight * index) / 4;
    context.beginPath();
    context.moveTo(left, y);
    context.lineTo(width - right, y);
    context.stroke();
    const label = Math.round(max * (1 - index / 4));
    context.fillText(String(label), 8, y + 4);
  }

  const coordinates = points.map((point, index) => ({
    x: left + (innerWidth * index) / Math.max(1, points.length - 1),
    y: top + innerHeight - (point.value / max) * innerHeight,
  }));
  const gradient = context.createLinearGradient(0, top, 0, height - bottom);
  gradient.addColorStop(0, "rgba(111, 140, 255, .28)");
  gradient.addColorStop(1, "rgba(111, 140, 255, 0)");
  context.beginPath();
  coordinates.forEach((point, index) => index ? context.lineTo(point.x, point.y) : context.moveTo(point.x, point.y));
  context.lineTo(coordinates.at(-1).x, height - bottom);
  context.lineTo(coordinates[0].x, height - bottom);
  context.closePath();
  context.fillStyle = gradient;
  context.fill();
  context.beginPath();
  coordinates.forEach((point, index) => index ? context.lineTo(point.x, point.y) : context.moveTo(point.x, point.y));
  context.strokeStyle = palette.blue;
  context.lineWidth = 2;
  context.stroke();
  coordinates.forEach((point, index) => {
    context.beginPath();
    context.arc(point.x, point.y, 3, 0, Math.PI * 2);
    context.fillStyle = palette.blue;
    context.fill();
    context.fillStyle = palette.text;
    context.textAlign = "center";
    context.fillText(points[index].label, point.x, height - 9);
  });
  context.textAlign = "left";
}

function drawBars(container, points) {
  const { context, width, height } = prepareCanvas(container);
  const left = Math.min(112, width * 0.34);
  const right = 30;
  const top = 12;
  const rowHeight = (height - top * 2) / Math.max(1, points.length);
  const max = Math.max(1, ...points.map((point) => point.value));
  const colors = [palette.red, palette.amber, palette.violet, palette.blue, palette.green];
  context.font = "11px ui-sans-serif, system-ui";
  points.forEach((point, index) => {
    const y = top + index * rowHeight + rowHeight * 0.28;
    const barHeight = Math.min(16, rowHeight * 0.42);
    const available = width - left - right;
    context.fillStyle = palette.text;
    context.textAlign = "right";
    context.fillText(point.label, left - 10, y + barHeight - 3);
    context.fillStyle = palette.grid;
    context.fillRect(left, y, available, barHeight);
    context.fillStyle = colors[index % colors.length];
    context.fillRect(left, y, available * (point.value / max), barHeight);
    context.fillStyle = "#dce5f5";
    context.textAlign = "left";
    context.fillText(String(point.value), left + Math.min(available * (point.value / max) + 7, available - 10), y + barHeight - 3);
  });
  context.textAlign = "left";
}

function renderCharts() {
  document.querySelectorAll("[data-chart]").forEach((container) => {
    const points = chartPoints(container);
    if (!points.length) return;
    if (container.dataset.chart === "line") drawLine(container, points);
    else drawBars(container, points);
  });
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = "Copy"; }, 1600);
  } catch (_) {
    button.textContent = "Unavailable";
  }
});

let resizeTimer;
window.addEventListener("resize", () => {
  window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(renderCharts, 120);
});
window.addEventListener("DOMContentLoaded", renderCharts);
