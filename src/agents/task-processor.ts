#!/usr/bin/env node
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Task Processor for Claude Code
 *
 * This script runs inside Claude Code and processes Sandyaa tasks.
 * It watches for .pending files, reads the corresponding task,
 * and writes results back.
 */

const TASKS_DIR = './.sandyaa/tasks';
const POLL_INTERVAL = 1000; // Check every second

async function processTask(taskId: string): Promise<void> {
  const taskFile = path.join(TASKS_DIR, `${taskId}.md`);
  const resultFile = path.join(TASKS_DIR, `${taskId}-result.json`);
  const pendingFile = path.join(TASKS_DIR, `${taskId}.pending`);

  try {
    // Read task
    const taskContent = await fs.readFile(taskFile, 'utf-8');

    console.log(`Processing task ${taskId}...`);

    // Extract the actual prompt (everything after "## Task Prompt")
    const promptMatch = taskContent.match(/## Task Prompt\n([\s\S]*?)\n## Output Format/);
    if (!promptMatch) {
      throw new Error('Could not extract prompt from task file');
    }

    const prompt = promptMatch[1].trim();

    // Here, we would normally call Claude API, but since this IS running in Claude,
    // we need a different approach. For now, write a placeholder that explains
    // Claude needs to manually process this.

    const result = {
      error: 'Task processor needs to be executed by Claude Code',
      task: taskId,
      instructions: 'Claude should read the task file and write the JSON result to the result file'
    };

    await fs.writeFile(resultFile, JSON.stringify(result, null, 2));

    // Remove pending marker
    await fs.unlink(pendingFile).catch(() => {});

    console.log(`Task ${taskId} marked as needing Claude attention`);

  } catch (error) {
    console.error(`Error processing task ${taskId}:`, error);
  }
}

async function watchTasks(): Promise<void> {
  console.log('Task processor started, watching for tasks...');

  while (true) {
    try {
      // Ensure directory exists
      await fs.mkdir(TASKS_DIR, { recursive: true });

      // List all .pending files
      const files = await fs.readdir(TASKS_DIR);
      const pendingFiles = files.filter(f => f.endsWith('.pending'));

      for (const pendingFile of pendingFiles) {
        const taskId = pendingFile.replace('.pending', '');
        await processTask(taskId);
      }

    } catch (error) {
      console.error('Error in task watcher:', error);
    }

    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL));
  }
}

// Start watching
watchTasks().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
