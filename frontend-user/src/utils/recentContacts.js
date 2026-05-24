const STORAGE_KEY = "cryptopulse_recent_transfers";

export function getRecentContacts() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];
    const contacts = JSON.parse(stored);
    return contacts.slice(0, 5);
  } catch {
    return [];
  }
}

export function addRecentContact(recipient) {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    let contacts = stored ? JSON.parse(stored) : [];
    
    contacts = contacts.filter(c => c.uid !== recipient.uid);
    
    contacts.unshift({
      uid: recipient.uid,
      name: recipient.name || recipient.email,
      timestamp: Date.now()
    });
    
    contacts = contacts.slice(0, 10);
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(contacts));
  } catch {
    // Silent fail
  }
}

export function clearRecentContacts() {
  localStorage.removeItem(STORAGE_KEY);
}
