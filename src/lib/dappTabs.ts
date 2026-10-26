import { forgetDappLoad } from "./dappLoadState";
import { closeDapp, dappLabel, isTauri } from "./platform";

/** Close each tab independently so a failed close can stay in the sidebar for retry. */
export async function closeDappTabs(ids: readonly string[]): Promise<{
  closed: string[];
  failed: { id: string; error: unknown }[];
}> {
  const results = await Promise.allSettled(ids.map(async (id) => {
    const label = dappLabel(id);
    if (isTauri()) await closeDapp(label);
    forgetDappLoad(label);
  }));
  const closed: string[] = [];
  const failed: { id: string; error: unknown }[] = [];
  results.forEach((result, index) => {
    if (result.status === "fulfilled") closed.push(ids[index]);
    else failed.push({ id: ids[index], error: result.reason });
  });
  return { closed, failed };
}
