#pragma once
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

#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <rex/string/key.h>
#include <rex/system/xobject.h>
#include <rex/system/xtypes.h>
#include <rex/thread/mutex.h>

namespace rex::stream {
class ByteStream;
}  // namespace rex::stream

namespace rex::system::util {

class ObjectTable {
 public:
  ObjectTable();
  ~ObjectTable();

  void Reset();

  X_STATUS AddHandle(XObject* object, X_HANDLE* out_handle);
  X_STATUS DuplicateHandle(X_HANDLE orig, X_HANDLE* out_handle);
  X_STATUS RetainHandle(X_HANDLE handle);
  X_STATUS ReleaseHandle(X_HANDLE handle);
  X_STATUS RemoveHandle(X_HANDLE handle);

  bool Save(stream::ByteStream* stream);
  bool Restore(stream::ByteStream* stream);

  // Restores a XObject reference with a handle. Mainly for internal use - do
  // not use.
  X_STATUS RestoreHandle(X_HANDLE handle, XObject* object);

  template <typename T>
  object_ref<T> LookupObject(X_HANDLE handle) {
    auto object = LookupObject(handle);
    if (object) {
      if (object->type() != T::kObjectType) {
        object->Release();
        return object_ref<T>();
      }
    }
    auto result = object_ref<T>(reinterpret_cast<T*>(object));
    return result;
  }

  X_STATUS AddNameMapping(const std::string_view name, X_HANDLE handle);
  void RemoveNameMapping(const std::string_view name);
  X_STATUS GetObjectByName(const std::string_view name, X_HANDLE* out_handle);
  template <typename T>
  std::vector<object_ref<T>> GetObjectsByType(XObject::Type type) {
    std::vector<object_ref<T>> results;
    GetObjectsByType(type, reinterpret_cast<std::vector<object_ref<XObject>>*>(&results));
    return results;
  }

  template <typename T>
  std::vector<object_ref<T>> GetObjectsByType() {
    std::vector<object_ref<T>> results;
    GetObjectsByType(T::kObjectType, reinterpret_cast<std::vector<object_ref<XObject>>*>(&results));
    return results;
  }

  std::vector<object_ref<XObject>> GetAllObjects();
  void PurgeAllObjects();  // Purges the object table of all guest objects

 private:
  struct ObjectTableEntry {
    int handle_ref_count = 0;
    XObject* object = nullptr;
  };

  // NOTE: the table is protected by table_mutex_ (a shared_mutex): the hot read path
  // (LookupObject) takes a SHARED lock so concurrent guest threads resolve handles in
  // parallel; mutations take an EXCLUSIVE lock. The *Locked helpers assume the exclusive
  // lock is already held (shared_mutex is non-recursive). Object Release()/destruction is
  // NEVER done while table_mutex_ is held (it re-enters the global lock via ~XThread) —
  // victims are collected under the lock and released after unlock. See
  // docs/research/gameplay-60fps-perf-plan.md.
  ObjectTableEntry* LookupTable(X_HANDLE handle);  // caller holds table_mutex_
  XObject* LookupObject(X_HANDLE handle);
  void GetObjectsByType(XObject::Type type, std::vector<object_ref<XObject>>* results);
  // Removes the handle assuming table_mutex_ is held exclusively. Does NOT Release the
  // object or remove its name mapping — those are returned for the caller to do AFTER
  // dropping the lock (avoids the table->global lock-ordering deadlock).
  X_STATUS RemoveHandleLocked(X_HANDLE handle, XObject** out_release, std::string* out_name);

  X_HANDLE TranslateHandle(X_HANDLE handle);
  static constexpr uint32_t GetHandleSlot(X_HANDLE handle) {
    return (handle - XObject::kHandleBase) >> 2;
  }
  X_STATUS FindFreeSlotLocked(uint32_t* out_slot);  // caller holds table_mutex_
  bool ResizeLocked(uint32_t new_capacity);         // caller holds table_mutex_

  std::shared_mutex table_mutex_;
  std::mutex name_mutex_;
  uint32_t table_capacity_ = 0;
  ObjectTableEntry* table_ = nullptr;
  uint32_t last_free_entry_ = 0;
  std::unordered_map<string::string_key_case, X_HANDLE> name_table_;
};

// Generic lookup
template <>
object_ref<XObject> ObjectTable::LookupObject<XObject>(X_HANDLE handle);

}  // namespace rex::system::util
