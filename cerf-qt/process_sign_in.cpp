#include "process_sign_in.h"

#include <atomic>

namespace cerffrontend {

namespace {

std::atomic<bool> signed_in{false};

}

bool ProcessSignIn::SignedIn() { return signed_in.load(std::memory_order_acquire); }

void ProcessSignIn::SignIn() { signed_in.store(true, std::memory_order_release); }

void ProcessSignIn::SignOut() { signed_in.store(false, std::memory_order_release); }

}
