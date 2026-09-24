export interface PullFilesClient {
  listPullFiles(owner: string, repo: string, pullNumber: number): Promise<string[]>;
}

export async function listChangedPaths(
  client: PullFilesClient,
  owner: string,
  repo: string,
  pullNumber: number,
): Promise<string[]> {
  return client.listPullFiles(owner, repo, pullNumber);
}
