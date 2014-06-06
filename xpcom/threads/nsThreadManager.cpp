/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsThreadManager.h"
#include "nsThread.h"
#include "nsThreadUtils.h"
#include "nsIClassInfoImpl.h"
#include "nsTArray.h"
#include "nsAutoPtr.h"
#include "mozilla/ThreadLocal.h"
#ifdef MOZ_CANARY
#include <fcntl.h>
#include <unistd.h>
#endif
#include <sys/types.h>

using namespace mozilla;

#ifdef XP_WIN
#include <windows.h>
DWORD gTLSThreadIDIndex = TlsAlloc();
#elif defined(NS_TLS)
NS_TLS mozilla::threads::ID gTLSThreadID = mozilla::threads::Generic;
#endif

static mozilla::ThreadLocal<bool> sTLSIsMainThread;

bool
NS_IsMainThread()
{
  return sTLSIsMainThread.get();
}

void
NS_SetMainThread()
{
  if (!sTLSIsMainThread.initialized()) {
    if (!sTLSIsMainThread.init()) {
      MOZ_CRASH();
    }
    sTLSIsMainThread.set(true);
  }
  MOZ_ASSERT(NS_IsMainThread());
}

typedef nsTArray<nsRefPtr<nsThread>> nsThreadArray;

class NotifyAllThreadsHasIdled: public nsRunnable
{
public:

  NotifyAllThreadsHasIdled(
    nsTArray<nsRefPtr<nsThreadManager::AllThreadHadIdledListener>>* aListeners)
    : mListeners(aListeners)
  {
  }

  virtual NS_IMETHODIMP
  Run() {
    // Copy listener array, which may be modified during call back.
    nsTArray<nsRefPtr<nsThreadManager::AllThreadHadIdledListener>> arr(*mListeners);
    for (int i = 0; i < arr.Length(); i++) {
      arr[i]->OnAllThreadHadIdled();
    }
    return NS_OK;
  }

private:
  // Raw pointer, since its member object of thread manager.
  nsTArray<nsRefPtr<nsThreadManager::AllThreadHadIdledListener>>* mListeners;
};

struct nsThreadManager::ThreadStatusInfo {
  bool mWorking;
  bool mWillBeWorking;
  bool mIgnored;
  ThreadStatusInfo()
    : mWorking(false)
    , mWillBeWorking(false)
    , mIgnored(false)
  {
  }
};

//-----------------------------------------------------------------------------

static void
ReleaseObject(void* aData)
{
  static_cast<nsISupports*>(aData)->Release();
}

static void
DeleteThreadStatusInfo(void* aData)
{
  delete static_cast<nsThreadManager::ThreadStatusInfo*>(aData);
}

static PLDHashOperator
AppendAndRemoveThread(PRThread* aKey, nsRefPtr<nsThread>& aThread, void* aArg)
{
  nsThreadArray* threads = static_cast<nsThreadArray*>(aArg);
  threads->AppendElement(aThread);
  return PL_DHASH_REMOVE;
}

// statically allocated instance
NS_IMETHODIMP_(MozExternalRefCountType)
nsThreadManager::AddRef()
{
  return 2;
}
NS_IMETHODIMP_(MozExternalRefCountType)
nsThreadManager::Release()
{
  return 1;
}
NS_IMPL_CLASSINFO(nsThreadManager, nullptr,
                  nsIClassInfo::THREADSAFE | nsIClassInfo::SINGLETON,
                  NS_THREADMANAGER_CID)
NS_IMPL_QUERY_INTERFACE_CI(nsThreadManager, nsIThreadManager)
NS_IMPL_CI_INTERFACE_GETTER(nsThreadManager, nsIThreadManager)

//-----------------------------------------------------------------------------

nsresult
nsThreadManager::Init()
{
  // Child processes need to initialize the thread manager before they
  // initialize XPCOM in order to set up the crash reporter. This leads to
  // situations where we get initialized twice.
  if (mInitialized) {
    return NS_OK;
  }

  if (PR_NewThreadPrivateIndex(&mCurThreadIndex, ReleaseObject) == PR_FAILURE) {
    return NS_ERROR_FAILURE;
  }

  if (PR_NewThreadPrivateIndex(&mThreadStatusInfoIndex,
                               DeleteThreadStatusInfo) == PR_FAILURE) {
    return NS_ERROR_FAILURE;
  }

  mLock = new Mutex("nsThreadManager.mLock");
  mMonitor = new ReentrantMonitor("nsThreadManager.mMonitor");

#ifdef MOZ_CANARY
  const int flags = O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK;
  const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  char* env_var_flag = getenv("MOZ_KILL_CANARIES");
  sCanaryOutputFD =
    env_var_flag ? (env_var_flag[0] ? open(env_var_flag, flags, mode) :
                                      STDERR_FILENO) :
                   0;
#endif

  // Setup "main" thread
  mMainThread = new nsThread(nsThread::MAIN_THREAD, 0);

  nsresult rv = mMainThread->InitCurrentThread();
  if (NS_FAILED(rv)) {
    mMainThread = nullptr;
    return rv;
  }

  // We need to keep a pointer to the current thread, so we can satisfy
  // GetIsMainThread calls that occur post-Shutdown.
  mMainThread->GetPRThread(&mMainPRThread);

#ifdef XP_WIN
  TlsSetValue(gTLSThreadIDIndex, (void*)mozilla::threads::Main);
#elif defined(NS_TLS)
  gTLSThreadID = mozilla::threads::Main;
#endif

  mInitialized = true;
  return NS_OK;
}

void
nsThreadManager::Shutdown()
{
  MOZ_ASSERT(NS_IsMainThread(), "shutdown not called from main thread");

  // Prevent further access to the thread manager (no more new threads!)
  //
  // XXX What happens if shutdown happens before NewThread completes?
  //     Fortunately, NewThread is only called on the main thread for now.
  //
  mInitialized = false;

  // Empty the main thread event queue before we begin shutting down threads.
  NS_ProcessPendingEvents(mMainThread);

  // We gather the threads from the hashtable into a list, so that we avoid
  // holding the hashtable lock while calling nsIThread::Shutdown.
  nsThreadArray threads;
  {
    MutexAutoLock lock(*mLock);
    mThreadsByPRThread.Enumerate(AppendAndRemoveThread, &threads);
  }

  // It's tempting to walk the list of threads here and tell them each to stop
  // accepting new events, but that could lead to badness if one of those
  // threads is stuck waiting for a response from another thread.  To do it
  // right, we'd need some way to interrupt the threads.
  //
  // Instead, we process events on the current thread while waiting for threads
  // to shutdown.  This means that we have to preserve a mostly functioning
  // world until such time as the threads exit.

  // Shutdown all threads that require it (join with threads that we created).
  for (uint32_t i = 0; i < threads.Length(); ++i) {
    nsThread* thread = threads[i];
    if (thread->ShutdownRequired()) {
      thread->Shutdown();
    }
  }

  // In case there are any more events somehow...
  NS_ProcessPendingEvents(mMainThread);

  // There are no more background threads at this point.

  // Clear the table of threads.
  {
    MutexAutoLock lock(*mLock);
    mThreadsByPRThread.Clear();
  }

  // Normally thread shutdown clears the observer for the thread, but since the
  // main thread is special we do it manually here after we're sure all events
  // have been processed.
  mMainThread->SetObserver(nullptr);
  mMainThread->ClearObservers();

  // Release main thread object.
  mMainThread = nullptr;
  mLock = nullptr;

  // Remove the TLS entry for the main thread.
  PR_SetThreadPrivate(mCurThreadIndex, nullptr);
  mThreadStatusInfos.RemoveElement(GetCurrentThreadStatusInfo());
  PR_SetThreadPrivate(mThreadStatusInfoIndex, nullptr);
}

void
nsThreadManager::RegisterCurrentThread(nsThread* aThread)
{
  MOZ_ASSERT(aThread->GetPRThread() == PR_GetCurrentThread(), "bad aThread");

  MutexAutoLock lock(*mLock);

  ++mCurrentNumberOfThreads;
  if (mCurrentNumberOfThreads > mHighestNumberOfThreads) {
    mHighestNumberOfThreads = mCurrentNumberOfThreads;
  }

  mThreadsByPRThread.Put(aThread->GetPRThread(), aThread);  // XXX check OOM?

  NS_ADDREF(aThread);  // for TLS entry
  PR_SetThreadPrivate(mCurThreadIndex, aThread);
}

void
nsThreadManager::UnregisterCurrentThread(nsThread* aThread)
{
  MOZ_ASSERT(aThread->GetPRThread() == PR_GetCurrentThread(), "bad aThread");

  MutexAutoLock lock(*mLock);

  --mCurrentNumberOfThreads;
  mThreadsByPRThread.Remove(aThread->GetPRThread());

  PR_SetThreadPrivate(mCurThreadIndex, nullptr);
  // Ref-count balanced via ReleaseObject
  mThreadStatusInfos.RemoveElement(GetCurrentThreadStatusInfo());
  PR_SetThreadPrivate(mThreadStatusInfoIndex, nullptr);
}

nsThread*
nsThreadManager::GetCurrentThread()
{
  // read thread local storage
  void* data = PR_GetThreadPrivate(mCurThreadIndex);
  if (data) {
    return static_cast<nsThread*>(data);
  }

  if (!mInitialized) {
    return nullptr;
  }

  // OK, that's fine.  We'll dynamically create one :-)
  nsRefPtr<nsThread> thread = new nsThread(nsThread::NOT_MAIN_THREAD, 0);
  if (!thread || NS_FAILED(thread->InitCurrentThread())) {
    return nullptr;
  }

  return thread.get();  // reference held in TLS
}

nsThreadManager::ThreadStatusInfo*
nsThreadManager::GetCurrentThreadStatusInfo()
{
  void* data = PR_GetThreadPrivate(mThreadStatusInfoIndex);
  if (!data) {
    ThreadStatusInfo *thrInfo = new ThreadStatusInfo();
    PR_SetThreadPrivate(mThreadStatusInfoIndex, thrInfo);
    mThreadStatusInfos.AppendElement(thrInfo);
    data = thrInfo;
  }

  return static_cast<ThreadStatusInfo*>(data);
}

NS_IMETHODIMP
nsThreadManager::NewThread(uint32_t aCreationFlags,
                           uint32_t aStackSize,
                           nsIThread** aResult)
{
  // No new threads during Shutdown
  if (NS_WARN_IF(!mInitialized)) {
    return NS_ERROR_NOT_INITIALIZED;
  }

  nsThread* thr = new nsThread(nsThread::NOT_MAIN_THREAD, aStackSize);
  if (!thr) {
    return NS_ERROR_OUT_OF_MEMORY;
  }
  NS_ADDREF(thr);

  nsresult rv = thr->Init();
  if (NS_FAILED(rv)) {
    NS_RELEASE(thr);
    return rv;
  }

  // At this point, we expect that the thread has been registered in mThread;
  // however, it is possible that it could have also been replaced by now, so
  // we cannot really assert that it was added.

  *aResult = thr;
  return NS_OK;
}

NS_IMETHODIMP
nsThreadManager::GetThreadFromPRThread(PRThread* aThread, nsIThread** aResult)
{
  // Keep this functioning during Shutdown
  if (NS_WARN_IF(!mMainThread)) {
    return NS_ERROR_NOT_INITIALIZED;
  }
  if (NS_WARN_IF(!aThread)) {
    return NS_ERROR_INVALID_ARG;
  }

  nsRefPtr<nsThread> temp;
  {
    MutexAutoLock lock(*mLock);
    mThreadsByPRThread.Get(aThread, getter_AddRefs(temp));
  }

  NS_IF_ADDREF(*aResult = temp);
  return NS_OK;
}

NS_IMETHODIMP
nsThreadManager::GetMainThread(nsIThread** aResult)
{
  // Keep this functioning during Shutdown
  if (NS_WARN_IF(!mMainThread)) {
    return NS_ERROR_NOT_INITIALIZED;
  }
  NS_ADDREF(*aResult = mMainThread);
  return NS_OK;
}

NS_IMETHODIMP
nsThreadManager::GetCurrentThread(nsIThread** aResult)
{
  // Keep this functioning during Shutdown
  if (NS_WARN_IF(!mMainThread)) {
    return NS_ERROR_NOT_INITIALIZED;
  }
  *aResult = GetCurrentThread();
  if (!*aResult) {
    return NS_ERROR_OUT_OF_MEMORY;
  }
  NS_ADDREF(*aResult);
  return NS_OK;
}

NS_IMETHODIMP
nsThreadManager::GetIsMainThread(bool* aResult)
{
  // This method may be called post-Shutdown

  *aResult = (PR_GetCurrentThread() == mMainPRThread);
  return NS_OK;
}

uint32_t
nsThreadManager::GetHighestNumberOfThreads()
{
  MutexAutoLock lock(*mLock);
  return mHighestNumberOfThreads;
}

void
nsThreadManager::SetIgnoreThreadStatus(bool aIgnored)
{
  GetCurrentThreadStatusInfo()->mIgnored = aIgnored;
}

void
nsThreadManager::SetThreadIdle()
{
  SetThreadStatus(false);
}

void
nsThreadManager::SetThreadWorking()
{
  SetThreadStatus(true);
}

void
nsThreadManager::AddAllThreadHadIdledListener(AllThreadHadIdledListener *listener)
{
  mThreadsIdledListener.AppendElement(listener);
}

void
nsThreadManager::RemoveAllThreadHadIdledListener(AllThreadHadIdledListener *listener)
{
  mThreadsIdledListener.RemoveElement(listener);
}

void
nsThreadManager::SetThreadStatus(bool isWorking)
{
  ThreadStatusInfo *currInfo = GetCurrentThreadStatusInfo();
  currInfo->mWillBeWorking = isWorking;
  if (mThreadsIdledListener.Length() > 0) {
    // If there's a listener, we update our status and check statuses of threads
    // after holding a lock.
    // There may be threads that checked |mThreadsIdledListener| before a
    // listener is put into it and then is context switched. In this case, we
    // might get the value before updated and the thread won't check again after
    // update to value.
    // a. If it goes from idle to working, we'll get incorrect idle status since
    //    there's actually something in its queue. However, having not finished
    //    the function means the thread that dispatches this task is still
    //    marked as working, and that will prevent us from firing an event.
    // b. If it goes from working to idle, we will get in incorrect working
    //    status. We could miss a chance to notify listeners if we are going to
    //    set current thread to idle. This can be addressed by storing status
    //    that is going to be set to |mWorking| to |mWillBeWorking|. If
    //    |mWillBeWorking| is false while |mWorking| is true, meaning the thread
    //    is becoming idle. Then we can treat the thread as an idle thread.
    //    We don't know if it will check threads, so we can just fire the event.
    //    And once we fired an event to main thread.
    bool hasWorkingThread = false;
    ReentrantMonitorAutoEnter mon(*mMonitor);
    // Get data structure of thread info.
    currInfo->mWorking = isWorking;
    for (int i = 0; i < mThreadStatusInfos.Length(); i++) {
      ThreadStatusInfo *info = mThreadStatusInfos[i];
      if (!info->mIgnored) {
        if (info->mWorking) {
          // Make sure it is not being updated.
          if (!info->mWillBeWorking) {
            hasWorkingThread = true;
            break;
          }
        }
      }
    }
    if (!hasWorkingThread) {
      nsRefPtr<NotifyAllThreadsHasIdled> runnable =
        new NotifyAllThreadsHasIdled(&mThreadsIdledListener);
      NS_DispatchToMainThread(runnable);
    }
  } else {
    // Update thread info without holding any lock.
    currInfo->mWorking = isWorking;
  }
}
