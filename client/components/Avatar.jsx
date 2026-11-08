import React, { useState, useSyncExternalStore } from 'react';
import { getProfileSnapshot, subscribeProfile } from '../state/profile.js';

export function Avatar({ size=26 }) {
  const profile=useSyncExternalStore(subscribeProfile,getProfileSnapshot);
  const [failed,setFailed]=useState(null);
  if(profile.avatar && failed!==profile.avatar) return <img className="reactAvatarImage" src={profile.avatar} alt="Аватар" onError={()=>setFailed(profile.avatar)} />;
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 21a8 8 0 0 0-16 0M12 13a4.5 4.5 0 1 0-4.5-4.5A4.5 4.5 0 0 0 12 13Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>;
}
