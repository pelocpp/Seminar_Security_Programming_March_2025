// =====================================================================================
// DynamicIntArray.h
// =====================================================================================

#pragma once

// ===========================================================================================
// Includes

#include <stdio.h>
#include <stdlib.h>  // malloc, free
#include <crtdbg.h>

// ===========================================================================================
// Defines

#define _CRTDBG_MAP_ALLOC

// ===========================================================================================
// Types

struct dynamicIntArray
{
// private:
    int*    m_data;
    size_t  m_length;
};

typedef struct dynamicIntArray DynamicIntArray;

// ===========================================================================================
// Function Prototypes

int    initDynamicIntArray                      (DynamicIntArray* array, size_t length);
void   releaseDynamicIntArray                   (DynamicIntArray* array);
void   createDynamicIntArrayFromArray           (DynamicIntArray* array, int* values, int length);
void   createDynamicIntArrayFromDynamicIntArray (DynamicIntArray* array, DynamicIntArray* other);
void   fillDynamicIntArray                      (DynamicIntArray* array, int value);
size_t getLength                                (DynamicIntArray* array);
int    get                                      (DynamicIntArray* array, int index);
void   set                                      (DynamicIntArray* array, int index, int value);
int    resizeDynamicIntArray                    (DynamicIntArray* array, int newLength);
int    shrinkToFitDynamicIntArray               (DynamicIntArray* array);
int    minimum                                  (DynamicIntArray* array);
int    maximum                                  (DynamicIntArray* array);
int    indexOf                                  (DynamicIntArray* array, int value);
int    equalsDynamicIntArray                    (DynamicIntArray* array, DynamicIntArray* other);
int    containsDynamicIntArray                  (DynamicIntArray* array, int value);
void   printDynamicIntArray                     (DynamicIntArray* array);

// =====================================================================================
// End-of-File
// =====================================================================================
