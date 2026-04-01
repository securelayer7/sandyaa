import * as fs from 'fs/promises';
import * as path from 'path';
import crypto from 'crypto';

export interface ProjectInfo {
  id: string;
  name: string;
  targetPath: string;
  createdAt: string;
  lastAnalyzed?: string;
  findingsDir: string;
  checkpointFile: string;
  tasksDir: string;
}

export class ProjectManager {
  private projectsFile: string;
  private baseDir: string;

  constructor(baseDir: string = '.sandyaa') {
    this.baseDir = baseDir;
    this.projectsFile = path.join(baseDir, 'projects.json');
  }

  /**
   * Get or create project for a target path
   * Returns existing project if target was analyzed before, otherwise creates new one
   */
  async getOrCreateProject(targetPath: string, projectName?: string): Promise<ProjectInfo> {
    const normalizedPath = path.resolve(targetPath);
    const projects = await this.loadProjects();

    // Check if project exists for this target
    const existing = projects.find(p => p.targetPath === normalizedPath);
    if (existing) {
      console.log(`Resuming project: ${existing.name} (${existing.id})`);
      return existing;
    }

    // Create new project
    const projectId = this.generateProjectId(normalizedPath);
    const name = projectName || path.basename(normalizedPath);

    const projectDir = path.join(this.baseDir, 'projects', projectId);
    await fs.mkdir(projectDir, { recursive: true });

    const project: ProjectInfo = {
      id: projectId,
      name,
      targetPath: normalizedPath,
      createdAt: new Date().toISOString(),
      findingsDir: path.join('findings', projectId),
      checkpointFile: path.join(projectDir, 'checkpoint.json'),
      tasksDir: path.join(projectDir, 'tasks')
    };

    // Create project directories
    await fs.mkdir(project.findingsDir, { recursive: true });
    await fs.mkdir(project.tasksDir, { recursive: true });

    // Save project
    projects.push(project);
    await this.saveProjects(projects);

    console.log(`Created new project: ${name} (${projectId})`);
    return project;
  }

  /**
   * List all projects
   */
  async listProjects(): Promise<ProjectInfo[]> {
    return await this.loadProjects();
  }

  /**
   * Delete project and all its data
   */
  async deleteProject(projectId: string): Promise<void> {
    const projects = await this.loadProjects();
    const project = projects.find(p => p.id === projectId);
    
    if (!project) {
      throw new Error(`Project ${projectId} not found`);
    }

    // Delete findings
    try {
      await fs.rm(project.findingsDir, { recursive: true, force: true });
    } catch {}

    // Delete project dir
    const projectDir = path.join(this.baseDir, 'projects', projectId);
    try {
      await fs.rm(projectDir, { recursive: true, force: true });
    } catch {}

    // Remove from projects list
    const updated = projects.filter(p => p.id !== projectId);
    await this.saveProjects(updated);

    console.log(`Deleted project: ${project.name}`);
  }

  private generateProjectId(targetPath: string): string {
    const hash = crypto.createHash('sha256').update(targetPath).digest('hex');
    return hash.substring(0, 12);
  }

  private async loadProjects(): Promise<ProjectInfo[]> {
    try {
      const data = await fs.readFile(this.projectsFile, 'utf-8');
      return JSON.parse(data);
    } catch {
      return [];
    }
  }

  private async saveProjects(projects: ProjectInfo[]): Promise<void> {
    await fs.mkdir(this.baseDir, { recursive: true });
    await fs.writeFile(this.projectsFile, JSON.stringify(projects, null, 2));
  }
}
