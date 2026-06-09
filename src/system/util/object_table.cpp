/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <algorithm>
#include <cstring>
#include <mutex>
#include <shared_mutex>

#include <rex/logging.h>
#include <rex/stream.h>
#include <rex/system/util/object_table.h>
#include <rex/system/xobject.h>
#include <rex/system/xthread.h>

namespace rex::system::util {

ObjectTable::ObjectTable() {}

ObjectTable::~ObjectTable() {
  Reset();
}

void ObjectTable::Reset() {
  // Collect victims under the lock, Release them after unlocking: object destruction
  // (~XThread -> UnregisterThread) re-enters the global lock, which must never be taken
  // while holding table_mutex_.
  std::vector<XObject*> to_release;
  {
    std::unique_lock<std::shared_mutex> lock(table_mutex_);
    for (uint32_t n = 0; n < table_capacity_; n++) {
      ObjectTableEntry& entry = table_[n];
      if (entry.object) {
        to_release.push_back(entry.object);
        entry.object = nullptr;
      }
    }
    table_capacity_ = 0;
    last_free_entry_ = 0;
    free(table_);
    table_ = nullptr;
  }
  for (XObject* object : to_release) {
    object->Release();
  }
}

X_STATUS ObjectTable::FindFreeSlotLocked(uint32_t* out_slot) {
  // Find a free slot.
  uint32_t slot = last_free_entry_;
  uint32_t scan_count = 0;
  while (scan_count < table_capacity_) {
    ObjectTableEntry& entry = table_[slot];
    if (!entry.object) {
      *out_slot = slot;
      return X_STATUS_SUCCESS;
    }
    scan_count++;
    slot = (slot + 1) % table_capacity_;
    if (slot == 0) {
      // Never allow 0 handles.
      scan_count++;
      slot++;
    }
  }

  // Table out of slots, expand.
  uint32_t new_table_capacity = std::max(16 * 1024u, table_capacity_ * 2);
  if (!ResizeLocked(new_table_capacity)) {
    return X_STATUS_NO_MEMORY;
  }

  // Never allow 0 handles.
  slot = ++last_free_entry_;
  *out_slot = slot;

  return X_STATUS_SUCCESS;
}

bool ObjectTable::ResizeLocked(uint32_t new_capacity) {
  uint32_t new_size = new_capacity * sizeof(ObjectTableEntry);
  uint32_t old_size = table_capacity_ * sizeof(ObjectTableEntry);
  auto new_table = reinterpret_cast<ObjectTableEntry*>(realloc(table_, new_size));
  if (!new_table) {
    return false;
  }

  // Zero out new entries.
  if (new_size > old_size) {
    std::memset(reinterpret_cast<uint8_t*>(new_table) + old_size, 0, new_size - old_size);
  }

  last_free_entry_ = table_capacity_;
  table_capacity_ = new_capacity;
  table_ = new_table;

  return true;
}

X_STATUS ObjectTable::AddHandle(XObject* object, X_HANDLE* out_handle) {
  X_STATUS result = X_STATUS_SUCCESS;

  uint32_t handle = 0;
  {
    std::unique_lock<std::shared_mutex> lock(table_mutex_);

    // Find a free slot.
    uint32_t slot = 0;
    result = FindFreeSlotLocked(&slot);

    // Stash.
    if (XSUCCEEDED(result)) {
      ObjectTableEntry& entry = table_[slot];
      entry.object = object;
      entry.handle_ref_count = 1;
      handle = XObject::kHandleBase + (slot << 2);
      object->handles().push_back(handle);

      // Retain so long as the object is in the table.
      object->Retain();

      REXSYS_NOISY_DEBUG("Added handle:{:08X} for {}", handle, typeid(*object).name());
    }
  }

  if (XSUCCEEDED(result)) {
    if (out_handle) {
      *out_handle = handle;
    }
  }

  return result;
}

X_STATUS ObjectTable::DuplicateHandle(X_HANDLE handle, X_HANDLE* out_handle) {
  X_STATUS result = X_STATUS_SUCCESS;
  handle = TranslateHandle(handle);

  // LookupObject (shared lock) releases its lock before AddHandle (exclusive lock) — no
  // nesting, no lock-ordering issue.
  XObject* object = LookupObject(handle);
  if (object) {
    result = AddHandle(object, out_handle);
    object->Release();  // Release the ref that LookupObject took
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

X_STATUS ObjectTable::RetainHandle(X_HANDLE handle) {
  std::unique_lock<std::shared_mutex> lock(table_mutex_);

  ObjectTableEntry* entry = LookupTable(handle);
  if (!entry) {
    return X_STATUS_INVALID_HANDLE;
  }

  entry->handle_ref_count++;
  return X_STATUS_SUCCESS;
}

X_STATUS ObjectTable::ReleaseHandle(X_HANDLE handle) {
  XObject* to_release = nullptr;
  std::string name_to_remove;
  X_STATUS result = X_STATUS_SUCCESS;
  {
    std::unique_lock<std::shared_mutex> lock(table_mutex_);

    ObjectTableEntry* entry = LookupTable(handle);
    if (!entry) {
      return X_STATUS_INVALID_HANDLE;
    }

    if (--entry->handle_ref_count == 0) {
      // No more references. Remove it from the table (under the same lock).
      result = RemoveHandleLocked(handle, &to_release, &name_to_remove);
    }
    // else: FIXME: a status code telling the caller it wasn't released (not a failure).
  }
  // Do the name-map removal and Release OUTSIDE table_mutex_ (object destruction
  // re-enters the global lock; name_mutex_ must not nest under table_mutex_).
  if (to_release) {
    if (!name_to_remove.empty()) {
      RemoveNameMapping(name_to_remove);
    }
    to_release->Release();
  }
  return result;
}

X_STATUS ObjectTable::RemoveHandle(X_HANDLE handle) {
  XObject* to_release = nullptr;
  std::string name_to_remove;
  X_STATUS result;
  {
    std::unique_lock<std::shared_mutex> lock(table_mutex_);
    result = RemoveHandleLocked(handle, &to_release, &name_to_remove);
  }
  if (to_release) {
    if (!name_to_remove.empty()) {
      RemoveNameMapping(name_to_remove);
    }
    to_release->Release();
  }
  return result;
}

// Assumes table_mutex_ is held EXCLUSIVELY. Detaches the object from the table but does
// NOT Release it or remove its name mapping — those are returned via out params for the
// caller to do after dropping the lock (see header note on the deadlock avoidance).
X_STATUS ObjectTable::RemoveHandleLocked(X_HANDLE handle, XObject** out_release,
                                         std::string* out_name) {
  *out_release = nullptr;

  handle = TranslateHandle(handle);
  if (!handle) {
    return X_STATUS_INVALID_HANDLE;
  }

  ObjectTableEntry* entry = LookupTable(handle);
  if (!entry) {
    return X_STATUS_INVALID_HANDLE;
  }

  if (entry->object) {
    auto object = entry->object;
    entry->object = nullptr;
    assert_zero(entry->handle_ref_count);
    entry->handle_ref_count = 0;

    // Walk the object's handles and remove this one.
    auto handle_entry = std::find(object->handles().begin(), object->handles().end(), handle);
    if (handle_entry != object->handles().end()) {
      object->handles().erase(handle_entry);
    }

    REXSYS_NOISY_DEBUG("Removed handle:{:08X} for {}", handle, typeid(*object).name());

    // Capture the name now (object is still alive under the lock) so the caller can clear
    // the name mapping after unlocking; defer the Release too.
    if (!object->name().empty()) {
      *out_name = object->name();
    }
    *out_release = object;
  }

  return X_STATUS_SUCCESS;
}

std::vector<object_ref<XObject>> ObjectTable::GetAllObjects() {
  std::shared_lock<std::shared_mutex> lock(table_mutex_);
  std::vector<object_ref<XObject>> results;

  for (uint32_t slot = 0; slot < table_capacity_; slot++) {
    auto& entry = table_[slot];
    if (entry.object && std::find(results.begin(), results.end(), entry.object) == results.end()) {
      entry.object->Retain();
      results.push_back(object_ref<XObject>(entry.object));
    }
  }

  return results;
}

void ObjectTable::PurgeAllObjects() {
  // Collect victims under the lock, Release after unlocking (see RemoveHandle).
  std::vector<XObject*> to_release;
  {
    std::unique_lock<std::shared_mutex> lock(table_mutex_);
    for (uint32_t slot = 0; slot < table_capacity_; slot++) {
      auto& entry = table_[slot];
      if (entry.object && !entry.object->is_host_object()) {
        entry.handle_ref_count = 0;
        to_release.push_back(entry.object);
        entry.object = nullptr;
      }
    }
  }
  for (XObject* object : to_release) {
    object->Release();
  }
}

// Assumes table_mutex_ is held (the only callers are writers holding it exclusively).
// Returns a raw entry pointer that is valid ONLY while that lock is continuously held.
ObjectTable::ObjectTableEntry* ObjectTable::LookupTable(X_HANDLE handle) {
  handle = TranslateHandle(handle);
  if (!handle) {
    return nullptr;
  }

  // Lower 2 bits are ignored.
  uint32_t slot = GetHandleSlot(handle);
  if (slot < table_capacity_) {
    return &table_[slot];
  }

  return nullptr;
}

// Generic lookup
template <>
object_ref<XObject> ObjectTable::LookupObject<XObject>(X_HANDLE handle) {
  auto object = ObjectTable::LookupObject(handle);
  auto result = object_ref<XObject>(reinterpret_cast<XObject*>(object));
  return result;
}

XObject* ObjectTable::LookupObject(X_HANDLE handle) {
  handle = TranslateHandle(handle);
  if (!handle) {
    return nullptr;
  }

  XObject* object = nullptr;
  {
    // SHARED lock: concurrent guest threads resolve handles in parallel. The table holds a
    // reference on every live object (taken in AddHandle, dropped only in RemoveHandle under
    // the EXCLUSIVE lock), so while we hold the shared lock the object cannot be destroyed,
    // and Retain() (atomic) is safe to do concurrently.
    std::shared_lock<std::shared_mutex> lock(table_mutex_);

    // Lower 2 bits are ignored.
    uint32_t slot = GetHandleSlot(handle);

    // Verify slot.
    if (slot < table_capacity_) {
      ObjectTableEntry& entry = table_[slot];
      if (entry.object) {
        object = entry.object;
        object->Retain();
      }
    }
  }

  return object;
}

void ObjectTable::GetObjectsByType(XObject::Type type, std::vector<object_ref<XObject>>* results) {
  std::shared_lock<std::shared_mutex> lock(table_mutex_);
  for (uint32_t slot = 0; slot < table_capacity_; ++slot) {
    auto& entry = table_[slot];
    if (entry.object) {
      if (entry.object->type() == type) {
        entry.object->Retain();
        results->push_back(object_ref<XObject>(entry.object));
      }
    }
  }
}

X_HANDLE ObjectTable::TranslateHandle(X_HANDLE handle) {
  if (handle == 0xFFFFFFFF) {
    // CurrentProcess
    // assert_always();
    return 0;
  } else if (handle == 0xFFFFFFFE) {
    // CurrentThread
    return XThread::GetCurrentThreadHandle();
  } else {
    return handle;
  }
}

X_STATUS ObjectTable::AddNameMapping(const std::string_view name, X_HANDLE handle) {
  std::lock_guard<std::mutex> name_lock(name_mutex_);
  if (name_table_.count(string::string_key_case(name))) {
    return X_STATUS_OBJECT_NAME_COLLISION;
  }
  name_table_.insert({string::string_key_case::create(name), handle});
  return X_STATUS_SUCCESS;
}

void ObjectTable::RemoveNameMapping(const std::string_view name) {
  // Names are case-insensitive.
  std::lock_guard<std::mutex> name_lock(name_mutex_);
  auto it = name_table_.find(string::string_key_case(name));
  if (it != name_table_.end()) {
    name_table_.erase(it);
  }
}

X_STATUS ObjectTable::GetObjectByName(const std::string_view name, X_HANDLE* out_handle) {
  // Names are case-insensitive.
  // Look up handle under name lock only -- do NOT hold name_mutex_ while
  // acquiring global lock (RemoveHandle takes global -> name ordering).
  X_HANDLE handle;
  {
    std::lock_guard<std::mutex> name_lock(name_mutex_);
    auto it = name_table_.find(string::string_key_case(name));
    if (it == name_table_.end()) {
      *out_handle = X_INVALID_HANDLE_VALUE;
      return X_STATUS_OBJECT_NAME_NOT_FOUND;
    }
    handle = it->second;
  }
  *out_handle = handle;

  // Retain via the normal LookupObject path (shared table lock).
  // The handle may have been removed between releasing name_mutex_ and the lookup --
  // LookupObject returns nullptr in that case.
  auto obj = LookupObject(handle);
  if (obj) {
    obj->RetainHandle();
    obj->Release();
  }

  return X_STATUS_SUCCESS;
}

bool ObjectTable::Save(stream::ByteStream* stream) {
  std::shared_lock<std::shared_mutex> lock(table_mutex_);
  stream->Write<uint32_t>(table_capacity_);
  for (uint32_t i = 0; i < table_capacity_; i++) {
    auto& entry = table_[i];
    stream->Write<int32_t>(entry.handle_ref_count);
  }

  return true;
}

bool ObjectTable::Restore(stream::ByteStream* stream) {
  std::unique_lock<std::shared_mutex> lock(table_mutex_);
  ResizeLocked(stream->Read<uint32_t>());
  for (uint32_t i = 0; i < table_capacity_; i++) {
    auto& entry = table_[i];
    // entry.object = nullptr;
    entry.handle_ref_count = stream->Read<int32_t>();
  }

  return true;
}

X_STATUS ObjectTable::RestoreHandle(X_HANDLE handle, XObject* object) {
  std::unique_lock<std::shared_mutex> lock(table_mutex_);
  uint32_t slot = GetHandleSlot(handle);
  assert_true(table_capacity_ > slot);

  if (table_capacity_ > slot) {
    auto& entry = table_[slot];
    entry.object = object;
    object->Retain();
  }

  return X_STATUS_SUCCESS;
}

}  // namespace rex::system::util
