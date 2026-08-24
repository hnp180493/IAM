import { laneList, type Lane, type Packet } from '../core/types';

const LANE_W = 200;
const TOP = 64;
const ROW_H = 58;

/**
 * The stage. k8sgames renders a spatial thing (a cluster) so it uses a 3D
 * scene; an auth flow is a temporal thing, so this is a sequence diagram that
 * draws itself one hop at a time. Same idea as their packet animation, different
 * axis: here the y axis IS time.
 */
export class Stage {
  private root: HTMLElement;
  private svg!: SVGSVGElement;
  private rowsGroup!: SVGGElement;
  private packets: Packet[] = [];
  private activeLanes: Lane[] = [];
  private selectedId: string | null = null;
  onSelect?: (packet: Packet) => void;

  constructor(root: HTMLElement) {
    this.root = root;
    this.build();
  }

  private build(): void {
    this.root.innerHTML = '';
    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.setAttribute('class', 'stage-svg');
    this.rowsGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    this.svg.appendChild(this.rowsGroup);
    this.root.appendChild(this.svg);
  }

  private laneX(lane: Lane): number {
    const idx = this.activeLanes.indexOf(lane);
    return idx * LANE_W + LANE_W / 2;
  }

  /** Lanes are per-flow: a machine-to-machine flow has no Browser column. */
  setLanes(lanes: Lane[]): void {
    this.activeLanes = lanes;
    this.packets = [];
    this.selectedId = null;
    const width = lanes.length * LANE_W;
    this.svg.setAttribute('viewBox', `0 0 ${width} ${TOP + ROW_H * 14}`);
    this.svg.setAttribute('width', String(width));
    this.rowsGroup.innerHTML = '';
    this.drawLanes();
  }

  private drawLanes(): void {
    const ns = 'http://www.w3.org/2000/svg';
    const height = TOP + ROW_H * 14;
    for (const laneId of this.activeLanes) {
      const meta = laneList().find((l) => l.id === laneId)!;
      const x = this.laneX(laneId);

      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', String(x));
      line.setAttribute('x2', String(x));
      line.setAttribute('y1', String(TOP - 8));
      line.setAttribute('y2', String(height));
      line.setAttribute('class', `lane-line lane-${laneId}`);
      this.rowsGroup.appendChild(line);

      const box = document.createElementNS(ns, 'rect');
      box.setAttribute('x', String(x - 78));
      box.setAttribute('y', '14');
      box.setAttribute('width', '156');
      box.setAttribute('height', '40');
      box.setAttribute('rx', '10');
      box.setAttribute('class', `lane-head lane-${laneId}`);
      this.rowsGroup.appendChild(box);

      const label = document.createElementNS(ns, 'text');
      label.setAttribute('x', String(x));
      label.setAttribute('y', '30');
      label.setAttribute('class', 'lane-label');
      label.textContent = meta.label;
      this.rowsGroup.appendChild(label);

      const sub = document.createElementNS(ns, 'text');
      sub.setAttribute('x', String(x));
      sub.setAttribute('y', '44');
      sub.setAttribute('class', 'lane-sub');
      sub.textContent = meta.sub;
      this.rowsGroup.appendChild(sub);
    }
  }

  clear(): void {
    this.setLanes(this.activeLanes);
  }

  /** Append one hop and grow the canvas to fit it. */
  addPacket(p: Packet): void {
    const ns = 'http://www.w3.org/2000/svg';
    const row = this.packets.length;
    this.packets.push(p);
    const y = TOP + 24 + row * ROW_H;

    const height = y + ROW_H * 2;
    this.svg.setAttribute('viewBox', `0 0 ${this.activeLanes.length * LANE_W} ${height}`);
    this.svg.style.height = `${height}px`;

    const x1 = this.laneX(p.from);
    const x2 = this.laneX(p.to);
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('class', `hop hop-${p.tone}`);
    g.dataset['packetId'] = p.id;

    const hit = document.createElementNS(ns, 'rect');
    hit.setAttribute('x', String(Math.min(x1, x2) - 12));
    hit.setAttribute('y', String(y - 26));
    hit.setAttribute('width', String(Math.abs(x2 - x1) + 24));
    hit.setAttribute('height', '46');
    hit.setAttribute('class', 'hop-hit');
    g.appendChild(hit);

    const arrow = document.createElementNS(ns, 'line');
    arrow.setAttribute('x1', String(x1));
    arrow.setAttribute('x2', String(x2));
    arrow.setAttribute('y1', String(y));
    arrow.setAttribute('y2', String(y));
    arrow.setAttribute('class', 'hop-arrow');
    arrow.setAttribute('marker-end', `url(#head-${p.tone})`);
    g.appendChild(arrow);

    const text = document.createElementNS(ns, 'text');
    text.setAttribute('x', String((x1 + x2) / 2));
    text.setAttribute('y', String(y - 8));
    text.setAttribute('class', 'hop-label');
    text.textContent = p.label;
    g.appendChild(text);

    if (p.tokens?.length) {
      const chip = document.createElementNS(ns, 'text');
      chip.setAttribute('x', String((x1 + x2) / 2));
      chip.setAttribute('y', String(y + 16));
      chip.setAttribute('class', 'hop-chip');
      chip.textContent = p.tokens.map((t) => t.label).join(' + ');
      g.appendChild(chip);
    }

    // The travelling dot: cheap, and it makes direction unmistakable.
    const dot = document.createElementNS(ns, 'circle');
    dot.setAttribute('r', '4');
    dot.setAttribute('cy', String(y));
    dot.setAttribute('class', 'hop-dot');
    const anim = document.createElementNS(ns, 'animate');
    anim.setAttribute('attributeName', 'cx');
    anim.setAttribute('from', String(x1));
    anim.setAttribute('to', String(x2));
    anim.setAttribute('dur', '0.55s');
    anim.setAttribute('fill', 'freeze');
    dot.appendChild(anim);
    g.appendChild(dot);

    g.addEventListener('click', () => this.select(p.id));
    this.rowsGroup.appendChild(g);

    this.root.scrollTo({ top: this.root.scrollHeight, behavior: 'smooth' });
  }

  select(id: string): void {
    this.selectedId = id;
    for (const el of this.rowsGroup.querySelectorAll('.hop')) {
      el.classList.toggle('is-selected', (el as SVGGElement).dataset['packetId'] === id);
    }
    const packet = this.packets.find((p) => p.id === id);
    if (packet) this.onSelect?.(packet);
  }

  get selected(): string | null {
    return this.selectedId;
  }

  /** Arrow heads, one per tone. Defined once, referenced by marker-end. */
  static defs(): string {
    const tones = [
      ['normal', '#8b93a7'],
      ['danger', '#f87171'],
      ['success', '#34d399'],
      ['blocked', '#fbbf24'],
    ];
    return `<svg width="0" height="0" style="position:absolute">${tones
      .map(
        ([tone, color]) =>
          `<defs><marker id="head-${tone}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="${color}"/></marker></defs>`,
      )
      .join('')}</svg>`;
  }
}
