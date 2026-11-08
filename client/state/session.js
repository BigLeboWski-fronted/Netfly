let snapshot = { user:null, syncStatus:'ok', loggingOut:false };
let logoutAction = null;
const listeners = new Set();
let sessionGeneration=0;
export const getSessionVersion = () => sessionGeneration;
export const getSessionSnapshot = () => snapshot;
export function subscribeSession(listener){ listeners.add(listener); return () => listeners.delete(listener); }
function patch(value){ snapshot={...snapshot,...value}; listeners.forEach(listener=>listener()); }
export function setUser(user){ sessionGeneration++; patch({user:user || null}); }
export function setSyncStatus(syncStatus){ patch({syncStatus}); }
export function configureSession({logout}){ logoutAction=logout; }
export async function logout(){
  if(snapshot.loggingOut || !logoutAction)return;
  sessionGeneration++;
  patch({loggingOut:true});
  try {await logoutAction();} finally {patch({loggingOut:false});}
}

export async function restoreSession({ request, onAuthenticated, onAnonymous }) {
  const generation=++sessionGeneration;
  let data;
  try { data=await request('/api/me'); }
  catch { if(generation===sessionGeneration) onAnonymous(); return; }
  if(generation!==sessionGeneration) return;
  await onAuthenticated(data);
}
