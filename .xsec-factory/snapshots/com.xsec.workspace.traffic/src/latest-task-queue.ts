export type AsyncTask = () => Promise<void>;

export class LatestTaskQueue {
  private running = false;
  private pending?: AsyncTask;

  schedule(task: AsyncTask) {
    if (this.running) {
      this.pending = task;
      return;
    }
    this.start(task);
  }

  clearPending() {
    this.pending = undefined;
  }

  private start(task: AsyncTask) {
    this.running = true;
    void task().finally(() => {
      const next = this.pending;
      this.pending = undefined;
      if (next) this.start(next);
      else this.running = false;
    });
  }
}
