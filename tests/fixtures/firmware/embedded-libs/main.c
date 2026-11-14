/* SPDX-License-Identifier: Apache-2.0 */
/* Owned held-out firmware for the embedded signature set: a FreeRTOS application that calls into newlib, libm,
 * libgcc and (EMBSIG_HAL) the STM32F4 HAL, plus device-specific code of its own that no library signature may
 * name. Built by tools/embedded-signatures/build.py fixture with a toolchain the signatures were not built with.
 * It is never run. */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"
#include "queue.h"
#include "semphr.h"
#include "task.h"
#include "timers.h"

#ifdef EMBSIG_HAL
#include "stm32f4xx_hal.h"
static UART_HandleTypeDef console;
static TIM_HandleTypeDef ticker;
#else
uint32_t SystemCoreClock = 8000000;
#endif

struct sample {
    uint32_t sequence;
    int32_t value;
    float scaled;
};

static QueueHandle_t samples;
static SemaphoreHandle_t console_lock;
static TimerHandle_t watchdog;
static volatile uint32_t ticks_seen;
static volatile uint32_t sensor_register;
static char line[96];
static uint8_t frame[64];

/* Device-specific code: small accessors and helpers firmware is full of. */
uint32_t device_ticks(void) { return ticks_seen; }
void device_tick(void) { ticks_seen++; }
uint32_t device_sensor_raw(void) { return sensor_register & 0x0fffu; }

uint16_t device_crc16(const uint8_t *data, size_t length)
{
    uint16_t crc = 0xffff;
    while (length--) {
        crc ^= (uint16_t)*data++ << 8;
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static int compare_samples(const void *left, const void *right)
{
    const struct sample *a = left, *b = right;
    return (a->value > b->value) - (a->value < b->value);
}

int device_parse_command(const char *text, long *argument)
{
    static const char *const verbs[] = {"rate", "gain", "mode", "dump"};
    char verb[8] = {0};
    const char *space = strchr(text, ' ');
    size_t length = space ? (size_t)(space - text) : strlen(text);
    if (length >= sizeof verb) {
        return -1;
    }
    strncpy(verb, text, length);
    for (unsigned index = 0; index < sizeof verbs / sizeof verbs[0]; index++) {
        if (strcmp(verb, verbs[index]) == 0) {
            *argument = space ? strtol(space + 1, NULL, 0) : 0;
            return (int)index;
        }
    }
    return -2;
}

float device_filter(float previous, float input, float alpha)
{
    float filtered = previous + alpha * (input - previous);
    return sqrtf(fabsf(filtered)) * (filtered < 0 ? -1.0f : 1.0f);
}

double device_energy(const struct sample *window, size_t count)
{
    double sum = 0;
    for (size_t index = 0; index < count; index++) {
        sum += (double)window[index].value * window[index].value;
    }
    return count ? sum / (double)count : 0.0;
}

uint64_t device_uptime_us(uint32_t ticks, uint32_t hz) { return (uint64_t)ticks * 1000000u / hz; }

static void console_write(const char *text)
{
    xSemaphoreTake(console_lock, portMAX_DELAY);
#ifdef EMBSIG_HAL
    HAL_UART_Transmit(&console, (const uint8_t *)text, (uint16_t)strlen(text), 100);
#else
    fputs(text, stdout);
#endif
    xSemaphoreGive(console_lock);
}

static void producer(void *context)
{
    (void)context;
    uint32_t sequence = 0;
    TickType_t wake = xTaskGetTickCount();
    for (;;) {
        struct sample sample = {sequence++, (int32_t)device_sensor_raw() - 2048, 0};
        sample.scaled = sinf((float)sample.value / 2048.0f) * cosf((float)sequence * 0.01f);
        xQueueSend(samples, &sample, portMAX_DELAY);
        vTaskDelayUntil(&wake, pdMS_TO_TICKS(10));
    }
}

static void consumer(void *context)
{
    (void)context;
    struct sample window[16];
    size_t filled = 0;
    float filtered = 0;
    for (;;) {
        if (xQueueReceive(samples, &window[filled], pdMS_TO_TICKS(100)) != pdPASS) {
            console_write("timeout\r\n");
            continue;
        }
        filtered = device_filter(filtered, window[filled].scaled, 0.25f);
        if (++filled == 16) {
            qsort(window, filled, sizeof window[0], compare_samples);
            double energy = device_energy(window, filled);
            snprintf(line, sizeof line, "median=%ld energy=%lu up=%llu f=%d\r\n", (long)window[8].value,
                     (unsigned long)energy, (unsigned long long)device_uptime_us(device_ticks(), 1000),
                     (int)(filtered * 1000.0f));
            console_write(line);
            memset(frame, 0, sizeof frame);
            memcpy(frame, line, strlen(line) < sizeof frame ? strlen(line) : sizeof frame);
            memmove(frame + 1, frame, sizeof frame - 1);
            frame[0] = (uint8_t)device_crc16(frame + 1, sizeof frame - 1);
            filled = 0;
        }
    }
}

static void shell(void *context)
{
    (void)context;
    long argument;
    char *buffer = malloc(64);
    for (;;) {
        strcpy(buffer, "rate 250");
        int verb = device_parse_command(buffer, &argument);
        if (verb >= 0) {
            snprintf(line, sizeof line, "verb %d arg %ld atan %d\r\n", verb, argument,
                     (int)(atan2f((float)argument, 3.0f) * 100.0f));
            console_write(line);
        }
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
        if (uxTaskGetStackHighWaterMark(NULL) < 32) {
            free(buffer);
            vTaskDelete(NULL);
        }
    }
}

static void watchdog_expired(TimerHandle_t timer)
{
    (void)timer;
    device_tick();
}

#ifdef EMBSIG_HAL
static void board_init(void)
{
    RCC_OscInitTypeDef oscillator = {0};
    RCC_ClkInitTypeDef clocks = {0};
    GPIO_InitTypeDef pins = {0};
    HAL_Init();
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
    oscillator.OscillatorType = RCC_OSCILLATORTYPE_HSE;
    oscillator.HSEState = RCC_HSE_ON;
    oscillator.PLL.PLLState = RCC_PLL_ON;
    oscillator.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    oscillator.PLL.PLLM = 8;
    oscillator.PLL.PLLN = 336;
    oscillator.PLL.PLLP = RCC_PLLP_DIV2;
    oscillator.PLL.PLLQ = 7;
    HAL_RCC_OscConfig(&oscillator);
    clocks.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    clocks.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    clocks.AHBCLKDivider = RCC_SYSCLK_DIV1;
    clocks.APB1CLKDivider = RCC_HCLK_DIV4;
    clocks.APB2CLKDivider = RCC_HCLK_DIV2;
    HAL_RCC_ClockConfig(&clocks, FLASH_LATENCY_5);
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_USART2_CLK_ENABLE();
    pins.Pin = GPIO_PIN_2 | GPIO_PIN_3;
    pins.Mode = GPIO_MODE_AF_PP;
    pins.Pull = GPIO_PULLUP;
    pins.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    pins.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &pins);
    console.Instance = USART2;
    console.Init.BaudRate = 115200;
    console.Init.WordLength = UART_WORDLENGTH_8B;
    console.Init.StopBits = UART_STOPBITS_1;
    console.Init.Parity = UART_PARITY_NONE;
    console.Init.Mode = UART_MODE_TX_RX;
    HAL_UART_Init(&console);
    __HAL_RCC_TIM2_CLK_ENABLE();
    ticker.Instance = TIM2;
    ticker.Init.Prescaler = 83;
    ticker.Init.Period = 999;
    HAL_TIM_Base_Init(&ticker);
    HAL_TIM_Base_Start_IT(&ticker);
    HAL_NVIC_SetPriority(TIM2_IRQn, 6, 0);
    HAL_NVIC_EnableIRQ(TIM2_IRQn);
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_SET);
}

void TIM2_IRQHandler(void) { HAL_TIM_IRQHandler(&ticker); }
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *timer)
{
    if (timer == &ticker) {
        HAL_IncTick();
        HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_5);
    }
}
#else
static void board_init(void) { sensor_register = 0x800; }
#endif

int main(void)
{
    board_init();
    samples = xQueueCreate(8, sizeof(struct sample));
    console_lock = xSemaphoreCreateMutex();
    watchdog = xTimerCreate("wdg", pdMS_TO_TICKS(500), pdTRUE, NULL, watchdog_expired);
    xTimerStart(watchdog, 0);
    xTaskCreate(producer, "prod", 256, NULL, 3, NULL);
    xTaskCreate(consumer, "cons", 512, NULL, 2, NULL);
    xTaskCreate(shell, "shell", 384, NULL, 1, NULL);
    vTaskStartScheduler();
    for (;;) {
    }
}
