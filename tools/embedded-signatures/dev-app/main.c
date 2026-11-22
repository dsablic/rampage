/* SPDX-License-Identifier: Apache-2.0 */
/* Owned development firmware for the embedded signature set: a FreeRTOS application calling into newlib, libm,
 * libgcc and (EMBSIG_HAL) the STM32F4 HAL, with code of its own that no library signature may name. It is the
 * dev split's program (tools/embedded-signatures/build.py dev), deliberately unlike the held-out fixture's
 * program, built with toolchains, options and a kernel configuration training does not use. It is never run. */
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "FreeRTOS.h"
#include "event_groups.h"
#include "queue.h"
#include "semphr.h"
#include "stream_buffer.h"
#include "task.h"
#include "timers.h"

#ifdef EMBSIG_HAL
#include "stm32f4xx_hal.h"
static SPI_HandleTypeDef flash_bus;
static I2C_HandleTypeDef sensor_bus;
static ADC_HandleTypeDef battery;
static CRC_HandleTypeDef checksum;
#else
uint32_t SystemCoreClock = 16000000;
#endif

#define EVENT_SAMPLE (1u << 0)
#define EVENT_FLUSH (1u << 1)
#define EVENT_ALARM (1u << 2)

struct record {
    uint16_t id;
    uint8_t kind;
    uint8_t flags;
    int64_t stamp;
    double reading;
};

static EventGroupHandle_t events;
static StreamBufferHandle_t log_stream;
static QueueHandle_t records;
static QueueHandle_t commands;
static QueueSetHandle_t inputs;
static SemaphoreHandle_t storage_lock;
static SemaphoreHandle_t credits;
static TimerHandle_t heartbeat;
static TaskHandle_t logger_task;
static volatile uint32_t adc_register;
static volatile uint32_t alarms;
static char text[128];
static struct record history[24];
static size_t history_count;

/* Program code: helpers of this firmware only. */
uint32_t app_adc_raw(void) { return adc_register & 0x3ffu; }

uint32_t app_fletcher32(const uint16_t *data, size_t words)
{
    uint32_t a = 0xffff, b = 0xffff;
    while (words) {
        size_t block = words > 359 ? 359 : words;
        words -= block;
        do {
            a += *data++;
            b += a;
        } while (--block);
        a = (a & 0xffff) + (a >> 16);
        b = (b & 0xffff) + (b >> 16);
    }
    return (b << 16) | a;
}

static int by_id(const void *left, const void *right)
{
    const struct record *a = left, *b = right;
    return (int)a->id - (int)b->id;
}

int app_tokenize(char *line, char **fields, int limit)
{
    int count = 0;
    char *cursor = line;
    while (*cursor && count < limit) {
        while (isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (!*cursor) {
            break;
        }
        fields[count++] = cursor;
        while (*cursor && !isspace((unsigned char)*cursor)) {
            *cursor = (char)toupper((unsigned char)*cursor);
            cursor++;
        }
        if (*cursor) {
            *cursor++ = '\0';
        }
    }
    return count;
}

double app_calibrate(uint32_t raw, double gain, double offset)
{
    double volts = (double)raw * 3.3 / 1023.0;
    double corrected = gain * volts + offset;
    return floor(corrected * 1000.0 + 0.5) / 1000.0 + fmod(corrected, 0.001) * 0.0;
}

float app_temperature(float resistance)
{
    float logr = logf(resistance / 10000.0f);
    return 1.0f / (0.001129148f + 0.000234125f * logr + 0.0000000876741f * logr * logr * logr) - 273.15f;
}

int64_t app_scale(int64_t value, int32_t numerator, int32_t denominator)
{
    return value * numerator / denominator + (value % denominator);
}

static void app_store(const struct record *entry)
{
    xSemaphoreTakeRecursive(storage_lock, portMAX_DELAY);
    if (history_count < sizeof history / sizeof history[0]) {
        history[history_count++] = *entry;
    } else {
        memmove(history, history + 1, sizeof history - sizeof history[0]);
        history[history_count - 1] = *entry;
    }
    xSemaphoreGiveRecursive(storage_lock);
}

static void app_log(const char *message)
{
    size_t length = strlen(message);
    xStreamBufferSend(log_stream, message, length, pdMS_TO_TICKS(5));
    xEventGroupSetBits(events, EVENT_FLUSH);
}

#ifdef EMBSIG_HAL
static void board_init(void)
{
    RCC_OscInitTypeDef oscillator = {0};
    RCC_ClkInitTypeDef clocks = {0};
    GPIO_InitTypeDef pins = {0};
    ADC_ChannelConfTypeDef channel = {0};
    HAL_Init();
    oscillator.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    oscillator.HSIState = RCC_HSI_ON;
    oscillator.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    oscillator.PLL.PLLState = RCC_PLL_ON;
    oscillator.PLL.PLLSource = RCC_PLLSOURCE_HSI;
    oscillator.PLL.PLLM = 16;
    oscillator.PLL.PLLN = 336;
    oscillator.PLL.PLLP = RCC_PLLP_DIV4;
    oscillator.PLL.PLLQ = 7;
    HAL_RCC_OscConfig(&oscillator);
    clocks.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    clocks.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    clocks.AHBCLKDivider = RCC_SYSCLK_DIV1;
    clocks.APB1CLKDivider = RCC_HCLK_DIV2;
    clocks.APB2CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&clocks, FLASH_LATENCY_2);
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_SPI1_CLK_ENABLE();
    __HAL_RCC_I2C1_CLK_ENABLE();
    __HAL_RCC_ADC1_CLK_ENABLE();
    __HAL_RCC_CRC_CLK_ENABLE();
    pins.Pin = GPIO_PIN_6 | GPIO_PIN_7;
    pins.Mode = GPIO_MODE_AF_OD;
    pins.Pull = GPIO_NOPULL;
    pins.Speed = GPIO_SPEED_FREQ_HIGH;
    pins.Alternate = GPIO_AF4_I2C1;
    HAL_GPIO_Init(GPIOB, &pins);
    flash_bus.Instance = SPI1;
    flash_bus.Init.Mode = SPI_MODE_MASTER;
    flash_bus.Init.Direction = SPI_DIRECTION_2LINES;
    flash_bus.Init.DataSize = SPI_DATASIZE_8BIT;
    flash_bus.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_8;
    flash_bus.Init.NSS = SPI_NSS_SOFT;
    HAL_SPI_Init(&flash_bus);
    sensor_bus.Instance = I2C1;
    sensor_bus.Init.ClockSpeed = 400000;
    sensor_bus.Init.DutyCycle = I2C_DUTYCYCLE_2;
    sensor_bus.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    HAL_I2C_Init(&sensor_bus);
    battery.Instance = ADC1;
    battery.Init.Resolution = ADC_RESOLUTION_10B;
    battery.Init.ScanConvMode = DISABLE;
    battery.Init.NbrOfConversion = 1;
    HAL_ADC_Init(&battery);
    channel.Channel = ADC_CHANNEL_8;
    channel.Rank = 1;
    channel.SamplingTime = ADC_SAMPLETIME_84CYCLES;
    HAL_ADC_ConfigChannel(&battery, &channel);
    checksum.Instance = CRC;
    HAL_CRC_Init(&checksum);
}

static uint32_t board_read_adc(void)
{
    HAL_ADC_Start(&battery);
    if (HAL_ADC_PollForConversion(&battery, 10) != HAL_OK) {
        return 0;
    }
    uint32_t value = HAL_ADC_GetValue(&battery);
    HAL_ADC_Stop(&battery);
    return value;
}

static void board_write_flash(const uint8_t *data, uint16_t length)
{
    uint8_t command[4] = {0x02, 0, 0, 0};
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0, GPIO_PIN_RESET);
    HAL_SPI_Transmit(&flash_bus, command, sizeof command, 20);
    HAL_SPI_Transmit(&flash_bus, (uint8_t *)data, length, 20);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0, GPIO_PIN_SET);
}

static int board_read_sensor(uint8_t reg, uint8_t *value)
{
    if (HAL_I2C_Master_Transmit(&sensor_bus, 0x48 << 1, &reg, 1, 10) != HAL_OK) {
        return -1;
    }
    return HAL_I2C_Master_Receive(&sensor_bus, 0x48 << 1, value, 1, 10) == HAL_OK ? 0 : -1;
}

static uint32_t board_checksum(const uint32_t *words, uint32_t count)
{
    return HAL_CRC_Calculate(&checksum, (uint32_t *)words, count);
}

void EXTI0_IRQHandler(void)
{
    BaseType_t woken = pdFALSE;
    __HAL_GPIO_EXTI_CLEAR_IT(GPIO_PIN_0);
    xEventGroupSetBitsFromISR(events, EVENT_ALARM, &woken);
    portYIELD_FROM_ISR(woken);
}
#else
static void board_init(void) { adc_register = 0x155; }
static uint32_t board_read_adc(void) { return app_adc_raw(); }
static void board_write_flash(const uint8_t *data, uint16_t length) { fwrite(data, 1, length, stdout); }
static int board_read_sensor(uint8_t reg, uint8_t *value)
{
    *value = (uint8_t)(reg ^ 0x5a);
    return 0;
}
static uint32_t board_checksum(const uint32_t *words, uint32_t count)
{
    return app_fletcher32((const uint16_t *)words, count * 2);
}

void EXTI0_IRQHandler(void)
{
    BaseType_t woken = pdFALSE;
    uint8_t command = 'a';
    alarms++;
    xQueueSendFromISR(commands, &command, &woken);
    portYIELD_FROM_ISR(woken);
}
#endif

void vApplicationStackOverflowHook(TaskHandle_t task, char *name)
{
    (void)task;
    (void)name;
    alarms |= 0x80000000u;
    for (;;) {
    }
}

void vApplicationMallocFailedHook(void) { alarms |= 0x40000000u; }

static StaticTask_t idle_task;
static StackType_t idle_stack[configMINIMAL_STACK_SIZE];
static StaticTask_t timer_task;
static StackType_t timer_stack[configTIMER_TASK_STACK_DEPTH];

void vApplicationGetIdleTaskMemory(StaticTask_t **task, StackType_t **stack, configSTACK_DEPTH_TYPE *depth)
{
    *task = &idle_task;
    *stack = idle_stack;
    *depth = configMINIMAL_STACK_SIZE;
}

void vApplicationGetTimerTaskMemory(StaticTask_t **task, StackType_t **stack, configSTACK_DEPTH_TYPE *depth)
{
    *task = &timer_task;
    *stack = timer_stack;
    *depth = configTIMER_TASK_STACK_DEPTH;
}

static void deferred_report(void *parameter, uint32_t value)
{
    (void)parameter;
    snprintf(text, sizeof text, "alarms=%lu credits=%lu\n", (unsigned long)value,
             (unsigned long)uxSemaphoreGetCount(credits));
    app_log(text);
}

static void heartbeat_expired(TimerHandle_t timer)
{
    uint32_t beats = (uint32_t)(uintptr_t)pvTimerGetTimerID(timer) + 1;
    vTimerSetTimerID(timer, (void *)(uintptr_t)beats);
    xEventGroupSetBits(events, EVENT_SAMPLE);
    if (beats % 16 == 0) {
        xTimerPendFunctionCall(deferred_report, NULL, alarms, 0);
        xTimerChangePeriod(timer, pdMS_TO_TICKS(250 + (rand() % 100)), 0);
    }
}

static void sampler(void *context)
{
    (void)context;
    uint16_t next = 0;
    TickType_t wake = xTaskGetTickCount();
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(events, EVENT_SAMPLE | EVENT_ALARM, pdTRUE, pdFALSE, portMAX_DELAY);
        uint8_t sensor = 0;
        struct record entry = {.id = next++, .kind = (bits & EVENT_ALARM) ? 2 : 1};
        if (board_read_sensor(0x01, &sensor) == 0) {
            entry.flags = sensor;
        }
        entry.stamp = app_scale((int64_t)xTaskGetTickCount() * 1000, 1000, configTICK_RATE_HZ);
        entry.reading = app_calibrate(board_read_adc(), 1.0125, -0.02) + (double)app_temperature(9000.0f + sensor);
        if (xQueueSend(records, &entry, 0) != pdPASS) {
            xSemaphoreGive(credits);
        }
        xTaskDelayUntil(&wake, pdMS_TO_TICKS(20));
    }
}

static void recorder(void *context)
{
    (void)context;
    for (;;) {
        QueueSetMemberHandle_t ready = xQueueSelectFromSet(inputs, portMAX_DELAY);
        if (ready == records) {
            struct record entry;
            xQueueReceive(records, &entry, 0);
            app_store(&entry);
            if (entry.reading > 40.0 || isnan(entry.reading)) {
                xTaskNotify(logger_task, entry.id, eSetValueWithOverwrite);
            }
        } else if (ready == commands) {
            uint8_t command;
            xQueueReceive(commands, &command, 0);
            if (command == 'f') {
                xSemaphoreTakeRecursive(storage_lock, portMAX_DELAY);
                qsort(history, history_count, sizeof history[0], by_id);
                struct record key = {.id = 7};
                struct record *found = bsearch(&key, history, history_count, sizeof history[0], by_id);
                if (found) {
                    board_write_flash((const uint8_t *)found, sizeof *found);
                }
                xSemaphoreGiveRecursive(storage_lock);
            }
        }
    }
}

static void logger(void *context)
{
    (void)context;
    char chunk[48];
    for (;;) {
        uint32_t id = 0;
        if (xTaskNotifyWait(0, UINT32_MAX, &id, pdMS_TO_TICKS(200)) == pdTRUE) {
            time_t now = (time_t)(1700000000 + id);
            struct tm parts;
            gmtime_r(&now, &parts);
            strftime(chunk, sizeof chunk, "%Y-%m-%dT%H:%M:%S", &parts);
            snprintf(text, sizeof text, "%s high reading #%lu\n", chunk, (unsigned long)id);
            app_log(text);
        }
        xEventGroupWaitBits(events, EVENT_FLUSH, pdTRUE, pdTRUE, pdMS_TO_TICKS(50));
        size_t received = xStreamBufferReceive(log_stream, chunk, sizeof chunk - 1, 0);
        if (received) {
            chunk[received] = '\0';
            board_write_flash((const uint8_t *)chunk, (uint16_t)received);
        }
    }
}

static void console(void *context)
{
    (void)context;
    char line[64];
    char *fields[6];
    for (;;) {
        strncpy(line, "set gain 1.5 0x20", sizeof line - 1);
        line[sizeof line - 1] = '\0';
        int count = app_tokenize(line, fields, 6);
        if (count >= 3 && strncmp(fields[0], "SET", 3) == 0) {
            double gain = strtod(fields[2], NULL);
            unsigned long mask = count > 3 ? strtoul(fields[3], NULL, 16) : 0;
            int whole = 0, part = 0;
            if (sscanf(fields[2], "%d.%d", &whole, &part) == 2 && memcmp(fields[1], "GAIN", 4) == 0) {
                snprintf(text, sizeof text, "gain %d.%d (%ld) mask %lx sqrt %d pow %d\n", whole, part,
                         labs((long)(gain * 100)), mask, (int)(sqrt(gain) * 100), (int)(pow(gain, 3.0) * 10));
                app_log(text);
            }
        } else if (strstr(line, "dump")) {
            uint32_t words[8];
            memcpy(words, history, sizeof words);
            div_t split = div(atoi(line + 5), 7);
            snprintf(text, sizeof text, "crc %08lx %d/%d\n", (unsigned long)board_checksum(words, 8), split.quot,
                     split.rem);
            app_log(text);
        }
        if (uxTaskPriorityGet(NULL) < 3) {
            vTaskPrioritySet(NULL, 3);
        }
        if (eTaskGetState(logger_task) == eSuspended) {
            vTaskResume(logger_task);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

int main(void)
{
    board_init();
    srand(12345);
    events = xEventGroupCreate();
    log_stream = xStreamBufferCreate(256, 1);
    records = xQueueCreate(6, sizeof(struct record));
    commands = xQueueCreate(4, sizeof(uint8_t));
    inputs = xQueueCreateSet(10);
    xQueueAddToSet(records, inputs);
    xQueueAddToSet(commands, inputs);
    storage_lock = xSemaphoreCreateRecursiveMutex();
    credits = xSemaphoreCreateCounting(8, 0);
    heartbeat = xTimerCreate("beat", pdMS_TO_TICKS(250), pdTRUE, NULL, heartbeat_expired);
    xTimerStart(heartbeat, 0);
    xTaskCreate(sampler, "samp", 320, NULL, 4, NULL);
    xTaskCreate(recorder, "rec", 384, NULL, 3, NULL);
    xTaskCreate(logger, "log", 448, NULL, 2, &logger_task);
    xTaskCreate(console, "con", 384, NULL, 1, NULL);
    vTaskStartScheduler();
    for (;;) {
    }
}
