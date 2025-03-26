// =====================================================================================
// DynamicIntArray.c
// =====================================================================================

#include <stdio.h>

#include "DynamicintArray.h"

// =====================================================================================

static int initDynamicIntArray(DynamicIntArray* da, size_t length)
{
    int* tmp = (int*) calloc(length, sizeof(int));
    if (tmp == NULL) {
        printf("initDynamicIntArray: Out of memory");
        return 0;
    }

    da->m_data = tmp;
    da->m_length = length;
    return 1;
}

static void releaseDynamicIntArray(DynamicIntArray* da)
{
    if (da->m_data != NULL) {

        free(da->m_data);

        da->m_data = NULL;
        da->m_length = 0;
    }
}

static void createDynamicIntArrayFromArray(DynamicIntArray* array, int* values, int length)
{
    array->m_data = (int*) malloc(sizeof(int) * length);
    if (array->m_data == (int*)0) {
        return;
    }

    for (int i = 0; i < length; i++) {
        array->m_data[i] = values[i];
    }

    array->m_length = length;
}

static void createDynamicIntArrayFromDynamicIntArray(DynamicIntArray* array, DynamicIntArray* other)
{
    array->m_data = (int*) malloc(sizeof(int) * other->m_length);
    if (array->m_data == (int*)0) {
        printf("Out of memory");
        return;
    }

    for (int i = 0; i < other->m_length; i++) {
        array->m_data[i] = other->m_data[i];
    }

    array->m_length = other->m_length;
}

static void fillDynamicIntArray(DynamicIntArray* array, int value)
{
    for (int i = 0; i < array->m_length; i++) {
        array->m_data[i] = value;
    }
}

static size_t getLength(DynamicIntArray* array)
{
    return array->m_length;
}

static int get(DynamicIntArray* array, int index)
{
    if (index >= 0 && index < array->m_length) {
        return array->m_data[index];
    }
    else {
        printf("Wrong Index: %d [Length = %zu]\n", index, array->m_length);
        return -1;
    }
}

static void set(DynamicIntArray* array, int index, int value)
{
    if (index >= 0 && index < array->m_length) {
        array->m_data[index] = value;
    }
    else {
        printf("Wrong Index: %d [Length = %zu]\n", index, array->m_length);
    }
}

static int resizeDynamicIntArray(DynamicIntArray* array, int newLength)
{
    if (newLength <= array->m_length)
    {
        // just shorten length, keep buffer
        array->m_length = newLength;

        return 1;
    }
    else {

        // allocate new (temporary) buffer
        int* tmp = (int*) calloc(newLength, sizeof(int));
        if (tmp == NULL) {
            printf("resizeDynamicIntArray: Out of memory");
            return 0;
        }
        else {

            // copy current buffer into new one
            // (rest of buffer is initialize with default values due to use of calloc)
            for (size_t i = 0; i < array->m_length; ++i) {
                tmp[i] = array->m_data[i];
            }

            // release current buffer
            free(array->m_data);

            // switch to new buffer
            array->m_data = tmp;
            array->m_length = newLength;

            return 1;
        }
    }
}

static int shrinkToFitDynamicIntArray(DynamicIntArray* array)
{
    // allocate new - temporary and fitting - buffer
    int* tmp = (int*) calloc(array->m_length, sizeof(int));
    if (tmp == NULL) {
        printf("shrinkToFitDynamicIntArray: Out of memory");
        return 0;
    }
    else {

        // copy current buffer into new one
        for (size_t i = 0; i < array->m_length; ++i) {
            tmp[i] = array->m_data[i];
        }

        // release current buffer
        free(array->m_data);

        // switch to new buffer
        array->m_data = tmp;

        return 1;
    }
}

static int minimum(DynamicIntArray* array)
{
    if (array->m_length == 0) {
        return 0;
    }

    int min = array->m_data[0];

    for (int i = 1; i < array->m_length; i++) {
        if (min > array->m_data[i]) {
            min = array->m_data[i];
        }
    }

    return min;
}

static int maximum(DynamicIntArray* array)
{
    if (array->m_length == 0) {
        return 0;
    }

    int max = array->m_data[0];

    for (int i = 1; i < array->m_length; i++) {
        if (max < array->m_data[i]) {
            max = array->m_data[i];
        }
    }

    return max;
}

static int indexOf(DynamicIntArray* array, int value)
{
    // perform a linear search
    for (int i = 0; i < array->m_length; i++) {
        if (array->m_data[i] == value) {
            return i;
        }
    }

    return -1;
}

static int equalsDynamicIntArray(DynamicIntArray* array, DynamicIntArray* other)
{
    if (array->m_length != other->m_length) {
        return 0;
    }

    for (int i = 0; i < array->m_length; i++) {
        if (array->m_data[i] != other->m_data[i]) {
            return 0;
        }
    }

    return 1;
}

static int containsDynamicIntArray(DynamicIntArray* array, int value)
{
    for (int i = 0; i < array->m_length; i++) {
        if (array->m_data[i] == value) {
            return 1;
        }
    }

    return 0;
}

static void printDynamicIntArray(DynamicIntArray* array)
{
    printf("{");
    for (int i = 0; i < array->m_length; i++)
    {
        printf("%d", array->m_data[i]);
        if (i < array->m_length - 1) {
            printf(",");
        }
    }
    printf("}\n");
}

// =====================================================================================
// =====================================================================================

static void exercise_DynamicIntArray_01()
{
    DynamicIntArray da = { NULL, 0 };

    releaseDynamicIntArray(&da);
}

static void exercise_DynamicIntArray_02()
{
    DynamicIntArray da = { NULL, 0 };

    initDynamicIntArray(&da, 10);

    printDynamicIntArray(&da);

    releaseDynamicIntArray(&da);
}

static void exercise_DynamicIntArray_03()
{
    DynamicIntArray da = { 0, 0 };

    int values[] = { 1, 2, 3, 4, 5 };

    createDynamicIntArrayFromArray(&da, values, 5);

    printDynamicIntArray(&da);

    resizeDynamicIntArray(&da, 10);

    printDynamicIntArray(&da);

    releaseDynamicIntArray(&da);

    printDynamicIntArray(&da);
}

static void exercise_DynamicIntArray_04()
{
    int values[] = { -10, -5, 0, 5, 10 };

    DynamicIntArray da = { 0, 0 };

    createDynamicIntArrayFromArray(&da, values, 5);

    printDynamicIntArray(&da);

    int min = minimum(&da);
    printf("Minimum: %d\n", min);

    int max = maximum(&da);
    printf("Maximum: %d\n", max);

    releaseDynamicIntArray(&da);
}

static void exercise_DynamicIntArray_05()
{
    int values[] = { 10, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    DynamicIntArray da = { 0, 0 };

    createDynamicIntArrayFromArray(&da, values, 10);

    printDynamicIntArray(&da);

    int n = get(&da, 5);
    printf("Value at index 5: %d\n", n);

    n = get(&da, -5);
    printf("Value at index -5: %d\n", n);

    set(&da, 5, 30);

    printDynamicIntArray(&da);

    releaseDynamicIntArray(&da);
}

static void exercise_DynamicIntArray_06()
{
    int values[] = { 10, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    DynamicIntArray da = { 0, 0 };

    createDynamicIntArrayFromArray(&da, values, 10);

    printDynamicIntArray(&da);

    // put into comments
    releaseDynamicIntArray(&da);

    _CrtDumpMemoryLeaks();
}

static void exercise_DynamicIntArray_07()
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    int values[] = { 10, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    DynamicIntArray da1 = { 0, 0 };

    createDynamicIntArrayFromArray(&da1, values, 10);

    // ------------------------
    // Standard C: Hmm, da wird eine neue Struktur-Variable
    // mit dem Inhalt einer vorhandenen Struktur vorbelegt.

    // Das ist bei dynamischen Daten falsch - und eine Schwachstelle !
    // DynamicIntArray sa2 = sa1;

    // Lösung
    DynamicIntArray da2;
    createDynamicIntArrayFromDynamicIntArray(&da2, &da1);

    printDynamicIntArray(&da1);
    printDynamicIntArray(&da2);

    releaseDynamicIntArray(&da1);
    releaseDynamicIntArray(&da2);

    _CrtDumpMemoryLeaks();
}

// =================================================================================
// ==========================================================================

void exercise_dynamic_int_array()
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    exercise_DynamicIntArray_01();
    exercise_DynamicIntArray_02();
    exercise_DynamicIntArray_03();
    exercise_DynamicIntArray_04();
    exercise_DynamicIntArray_05();
    exercise_DynamicIntArray_06();
    exercise_DynamicIntArray_07();
}

// =====================================================================================
// End-of-File
// =====================================================================================
