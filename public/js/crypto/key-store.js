const DATABASE = "trustsign-device-keys";
const STORE = "keys";

function openDatabase() {
  return new Promise((resolve, reject) => {
    const opening = indexedDB.open(DATABASE, 1);
    opening.onupgradeneeded = () => {
      if (!opening.result.objectStoreNames.contains(STORE)) {
        opening.result.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    opening.onsuccess = () => resolve(opening.result);
    opening.onerror = () => reject(opening.error || new Error("Không mở được IndexedDB."));
    opening.onblocked = () => reject(new Error("IndexedDB đang bị chặn bởi một tab TrustSign khác."));
  });
}

function transact(mode, action) {
  return openDatabase().then((database) => new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE, mode);
    const store = transaction.objectStore(STORE);
    let result;
    try {
      result = action(store);
    } catch (error) {
      database.close();
      reject(error);
      return;
    }
    transaction.oncomplete = () => {
      database.close();
      resolve(result?.result);
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error || new Error("Lỗi khi truy cập IndexedDB."));
    };
    transaction.onabort = () => {
      database.close();
      reject(transaction.error || new Error("Giao dịch IndexedDB bị hủy."));
    };
  }));
}

export function savePrivateKey(username, deviceId, privateKey) {
  const id = `${username}:${deviceId}`;
  return transact("readwrite", (store) => store.put({ id, username, deviceId, privateKey }));
}

export async function getPrivateKey(username, deviceId) {
  const value = await transact("readonly", (store) => store.get(`${username}:${deviceId}`));
  return value?.privateKey ?? null;
}

export function deletePrivateKey(username, deviceId) {
  return transact("readwrite", (store) => store.delete(`${username}:${deviceId}`));
}
