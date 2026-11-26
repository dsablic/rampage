/* SPDX-License-Identifier: Apache-2.0 */
/* Relocatable-object fixture (build-objects.sh): thread-local storage, whose relocations the loader reports as
 * unapplied. */
__thread int counter;

int bump(void) { return ++counter; }
