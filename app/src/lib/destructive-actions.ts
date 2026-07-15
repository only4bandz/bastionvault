export async function deleteInboxMessage(
  deleteRemote: () => Promise<void>,
  commitLocal: () => void,
  toast: (message: string) => void
): Promise<boolean> {
  try {
    await deleteRemote();
  } catch {
    toast("Message was not deleted");
    return false;
  }
  commitLocal();
  toast("Message deleted");
  return true;
}
