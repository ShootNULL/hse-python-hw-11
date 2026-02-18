import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import warnings
from collections import Counter
from datetime import datetime
import os

warnings.filterwarnings('ignore')

# Настройка стиля для графиков
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")


class BotsV1Analyzer:
    def __init__(self):
        self.winevent_df = None
        self.dns_df = None
        self.suspicious_events = {}

    def load_winevent_data(self, json_file_path):
        """Загрузка WinEvent логов из JSON файла"""
        print("Загрузка WinEvent логов...")

        try:
            with open(json_file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)

            # Извлекаем результаты из каждой записи
            records = []
            for item in data:
                if 'result' in item:
                    records.append(item['result'])

            self.winevent_df = pd.DataFrame(records)
            print(f"Загружено {len(self.winevent_df)} записей WinEvent логов")

            # Преобразование EventCode в числовой формат
            if 'EventCode' in self.winevent_df.columns:
                self.winevent_df['EventCode'] = pd.to_numeric(self.winevent_df['EventCode'], errors='coerce')

            # Обработка временных меток
            if '_time' in self.winevent_df.columns:
                self.winevent_df['_time'] = pd.to_datetime(self.winevent_df['_time'], errors='coerce')

            return True

        except Exception as e:
            print(f"Ошибка загрузки WinEvent логов: {e}")
            return False

    def load_dns_data(self, dns_file_path):
        """Загрузка DNS логов (если доступны)"""
        print("\nЗагрузка DNS логов...")

        try:
            # Проверяем существование файла
            if not os.path.exists(dns_file_path):
                print(f"Файл {dns_file_path} не найден. Создаем тестовые DNS данные...")
                self._create_sample_dns_data()
                return

            # Пытаемся загрузить DNS логи (формат может быть разным)
            if dns_file_path.endswith('.json'):
                with open(dns_file_path, 'r', encoding='utf-8') as file:
                    dns_data = json.load(file)
                self.dns_df = pd.DataFrame(dns_data)
            elif dns_file_path.endswith('.csv'):
                self.dns_df = pd.read_csv(dns_file_path)
            else:
                print(f"Неподдерживаемый формат файла. Создаем тестовые DNS данные...")
                self._create_sample_dns_data()
                return

            print(f"Загружено {len(self.dns_df)} записей DNS логов")

        except Exception as e:
            print(f"Ошибка загрузки DNS логов: {e}")
            print("Создаем тестовые DNS данные для демонстрации...")
            self._create_sample_dns_data()

    def _create_sample_dns_data(self):
        """Создание тестовых данных DNS логов"""
        np.random.seed(42)
        n_records = 500

        # Нормальные домены
        normal_domains = ['google.com', 'microsoft.com', 'amazon.com', 'facebook.com',
                          'twitter.com', 'github.com', 'stackoverflow.com', 'bing.com']

        # Подозрительные домены
        suspicious_domains = [
            'malware-domain.xyz', 'c2-server.top', 'phishing-site.work',
            'dga-generated.bid', 'suspicious-payload.trade', 'unknown-malware.date',
            'rare-domain.win', 'strange-pattern.cc', 'potential-c2.net',
            'data-exfil.info', 'encrypted-channel.org', 'suspicious-activity.ru'
        ]

        # Создаем распределение: 30% подозрительных, 70% нормальных
        domains = np.random.choice(suspicious_domains + normal_domains, n_records,
                                   p=[0.03] * len(suspicious_domains) + [0.7 / len(normal_domains)] * len(
                                       normal_domains))

        # Создаем IP адреса
        client_ips = [f'192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}'
                      for _ in range(n_records)]
        # Добавляем несколько внешних IP
        for i in range(10):
            client_ips[
                i] = f'{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}'

        self.dns_df = pd.DataFrame({
            'timestamp': pd.date_range('2016-08-28', periods=n_records, freq='30s'),
            'domain': domains,
            'client_ip': client_ips,
            'query_type': np.random.choice(['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'ANY'], n_records),
            'response_code': np.random.choice([0, 1, 2, 3, 5], n_records, p=[0.9, 0.02, 0.02, 0.03, 0.03]),
            'response_size': np.random.randint(50, 1500, n_records)
        })

        print("Созданы тестовые DNS данные")

    def analyze_winevent_logs(self):
        """Анализ WinEvent логов для поиска подозрительных событий"""
        print("\n" + "=" * 60)
        print("АНАЛИЗ WINEVENT ЛОГОВ")
        print("=" * 60)

        if self.winevent_df is None or len(self.winevent_df) == 0:
            print("Нет данных WinEvent для анализа")
            return {}

        # Определение подозрительных EventID и их описаний
        suspicious_events = {
            4624: {'name': 'Successful Logon', 'risk': 'Medium', 'desc': 'Account successfully logged on'},
            4625: {'name': 'Failed Logon', 'risk': 'High', 'desc': 'Account failed to log on'},
            4634: {'name': 'Logoff', 'risk': 'Low', 'desc': 'Account logged off'},
            4648: {'name': 'Logon with Explicit Credentials', 'risk': 'High',
                   'desc': 'Logon using explicit credentials'},
            4672: {'name': 'Special Privileges Assigned', 'risk': 'High',
                   'desc': 'Special privileges assigned to new logon'},
            4688: {'name': 'Process Creation', 'risk': 'Medium', 'desc': 'A new process has been created'},
            4689: {'name': 'Process Exit', 'risk': 'Low', 'desc': 'A process has exited'},
            4698: {'name': 'Scheduled Task Created', 'risk': 'High', 'desc': 'A scheduled task was created'},
            4703: {'name': 'Token Manipulation', 'risk': 'High', 'desc': 'A user right was adjusted'},
            4720: {'name': 'User Account Created', 'risk': 'High', 'desc': 'A user account was created'},
            4732: {'name': 'Member Added to Security Group', 'risk': 'High',
                   'desc': 'A member was added to a security group'},
            4768: {'name': 'Kerberos Ticket Request', 'risk': 'Medium',
                   'desc': 'A Kerberos authentication ticket was requested'},
            4769: {'name': 'Kerberos Service Ticket', 'risk': 'Medium',
                   'desc': 'A Kerberos service ticket was requested'},
            4776: {'name': 'Credential Validation', 'risk': 'Medium',
                   'desc': 'Domain controller validated credentials'},
            4798: {'name': 'User Group Membership', 'risk': 'Medium',
                   'desc': 'A user\'s group membership was enumerated'},
            4799: {'name': 'Security Group Membership', 'risk': 'Medium',
                   'desc': 'A security group\'s membership was enumerated'},
            5140: {'name': 'Share Accessed', 'risk': 'Medium', 'desc': 'A network share object was accessed'},
            5145: {'name': 'Share Access Check', 'risk': 'Medium',
                   'desc': 'A network share object was checked for access'},
            5156: {'name': 'Connection Allowed', 'risk': 'Low',
                   'desc': 'Windows Filtering Platform allowed a connection'},
            5158: {'name': 'Bind to Port', 'risk': 'Medium',
                   'desc': 'Windows Filtering Platform permitted a bind to a local port'},
            7045: {'name': 'Service Installed', 'risk': 'High', 'desc': 'A service was installed in the system'}
        }

        # Подсчет всех событий
        event_counts = self.winevent_df['EventCode'].value_counts()

        print(f"\nВсего уникальных EventID: {len(event_counts)}")
        print("\nТоп-10 наиболее частых событий:")
        for event_id, count in event_counts.head(10).items():
            event_info = suspicious_events.get(event_id, {'name': 'Unknown Event', 'risk': 'Unknown'})
            risk_symbol = "🔴" if event_info['risk'] == 'High' else "🟡" if event_info['risk'] == 'Medium' else "⚪"
            print(f"  {risk_symbol} Event {event_id}: {event_info['name']} - {count} записей")

        # Фильтрация подозрительных событий
        suspicious_mask = self.winevent_df['EventCode'].isin(suspicious_events.keys())
        suspicious_df = self.winevent_df[suspicious_mask]

        print(f"\nНайдено подозрительных событий: {len(suspicious_df)}")

        # Группировка по EventID
        suspicious_counts = suspicious_df['EventCode'].value_counts()

        # Формирование результата с описаниями
        result = {}
        for event_id, count in suspicious_counts.items():
            if event_id in suspicious_events:
                event_name = f"[{event_id}] {suspicious_events[event_id]['name']}"
                result[event_name] = count

        # Анализ по уровням риска
        risk_levels = {'High': 0, 'Medium': 0, 'Low': 0}
        for event_id in suspicious_df['EventCode'].unique():
            if event_id in suspicious_events:
                risk = suspicious_events[event_id]['risk']
                count = suspicious_counts[event_id]
                risk_levels[risk] += count

        print("\nРаспределение по уровням риска:")
        for risk, count in risk_levels.items():
            if risk == 'High':
                print(f"  🔴 {risk}: {count} событий")
            elif risk == 'Medium':
                print(f"  🟡 {risk}: {count} событий")
            else:
                print(f"  ⚪ {risk}: {count} событий")

        # Анализ по компьютерам
        computer_counts = suspicious_df['ComputerName'].value_counts().head(5)
        print("\nТоп-5 компьютеров с подозрительными событиями:")
        for computer, count in computer_counts.items():
            print(f"  💻 {computer}: {count} событий")

        self.suspicious_events['WinEvent'] = result
        return result

    def analyze_dns_logs(self):
        """Анализ DNS логов для поиска подозрительных запросов"""
        print("\n" + "=" * 60)
        print("АНАЛИЗ DNS ЛОГОВ")
        print("=" * 60)

        if self.dns_df is None or len(self.dns_df) == 0:
            print("Нет данных DNS для анализа")
            return {}

        suspicious_criteria = {}

        # 1. Анализ доменов
        domain_counts = self.dns_df['domain'].value_counts()

        # Редкие домены (появляются менее 3 раз)
        rare_domains = domain_counts[domain_counts < 3]
        suspicious_criteria['Rare Domain Queries'] = len(rare_domains)
        print(f"\n📊 Редкие домены (<3 запросов): {len(rare_domains)}")

        # Топ запрашиваемых доменов
        print("\nТоп-10 запрашиваемых доменов:")
        for domain, count in domain_counts.head(10).items():
            print(f"  🌐 {domain}: {count} запросов")

        # 2. Подозрительные TLD
        suspicious_tlds = ['.xyz', '.top', '.work', '.date', '.win', '.bid', '.trade', '.cc', '.info']

        def get_tld(domain):
            if pd.isna(domain):
                return ''
            parts = str(domain).split('.')
            return '.' + parts[-1] if len(parts) > 1 else ''

        self.dns_df['tld'] = self.dns_df['domain'].apply(get_tld)
        suspicious_tld_queries = self.dns_df[self.dns_df['tld'].isin(suspicious_tlds)]
        suspicious_criteria['Unusual TLD Queries'] = len(suspicious_tld_queries)
        print(f"\nЗапросы к подозрительным TLD: {len(suspicious_tld_queries)}")

        if len(suspicious_tld_queries) > 0:
            print("  Примеры подозрительных TLD:")
            for tld in suspicious_tld_queries['tld'].value_counts().head().index:
                count = suspicious_tld_queries['tld'].value_counts()[tld]
                print(f"    {tld}: {count} запросов")

        # 3. Подозрительные коды ответа (не 0 - успех)
        if 'response_code' in self.dns_df.columns:
            failed_responses = self.dns_df[self.dns_df['response_code'] != 0]
            suspicious_criteria['Failed DNS Responses'] = len(failed_responses)
            print(f"\nНеудачные DNS ответы: {len(failed_responses)}")

            if len(failed_responses) > 0:
                print("  Распределение кодов ответа:")
                for code, count in failed_responses['response_code'].value_counts().head().items():
                    print(f"    Код {code}: {count} запросов")

        # 4. Домены с длинными именами (потенциальный DGA)
        if 'domain' in self.dns_df.columns:
            self.dns_df['domain_length'] = self.dns_df['domain'].astype(str).apply(len)
            long_domains = self.dns_df[self.dns_df['domain_length'] > 30]
            suspicious_criteria['Long Domain Names (>30 chars)'] = len(long_domains)
            print(f"\n📏 Длинные имена доменов (>30 символов): {len(long_domains)}")

        # 5. Нестандартные типы запросов
        if 'query_type' in self.dns_df.columns:
            unusual_query_types = ['TXT', 'ANY', 'AXFR', 'CNAME']
            unusual_queries = self.dns_df[self.dns_df['query_type'].isin(unusual_query_types)]
            suspicious_criteria['Unusual Query Types'] = len(unusual_queries)
            print(f"\nНестандартные типы запросов: {len(unusual_queries)}")

            if len(unusual_queries) > 0:
                print("  Распределение по типам:")
                for qtype, count in unusual_queries['query_type'].value_counts().items():
                    print(f"    {qtype}: {count} запросов")

        # 6. Частота запросов с одного IP
        if 'client_ip' in self.dns_df.columns:
            ip_frequency = self.dns_df['client_ip'].value_counts()
            threshold = ip_frequency.mean() + 2 * ip_frequency.std()
            high_frequency_ips = ip_frequency[ip_frequency > threshold]
            suspicious_criteria['High Query Frequency IPs'] = len(high_frequency_ips)
            print(f"\nIP с высокой частотой запросов: {len(high_frequency_ips)}")

            if len(high_frequency_ips) > 0:
                print("  Топ подозрительных IP:")
                for ip, count in high_frequency_ips.head().items():
                    print(f"    {ip}: {count} запросов")

        self.suspicious_events['DNS'] = suspicious_criteria
        return suspicious_criteria

    def visualize_results(self):
        """Визуализация топ-10 подозрительных событий"""
        print("\n" + "=" * 60)
        print("ВИЗУАЛИЗАЦИЯ РЕЗУЛЬТАТОВ")
        print("=" * 60)

        # Подготовка данных для визуализации
        all_events = []

        for source, events in self.suspicious_events.items():
            for event_name, count in events.items():
                all_events.append({
                    'Source': 'WinEventLog' if source == 'WinEvent' else 'DNS Logs',
                    'Event': event_name,
                    'Count': count
                })

        if not all_events:
            print("Нет данных для визуализации")
            return

        df_viz = pd.DataFrame(all_events)

        # Сортировка и выбор топ-10
        top10 = df_viz.nlargest(10, 'Count')

        print("\nТоп-10 подозрительных событий:")
        for i, row in top10.iterrows():
            print(f"  {i + 1}. {row['Event']}: {row['Count']} ({row['Source']})")

        # Создание графиков
        fig = plt.figure(figsize=(16, 10))

        # График 1: Топ-10 подозрительных событий
        ax1 = plt.subplot(2, 2, 1)
        colors = ['#ff6b6b' if x == 'WinEventLog' else '#4ecdc4' for x in top10['Source']]
        bars = ax1.barh(range(len(top10)), top10['Count'], color=colors)
        ax1.set_yticks(range(len(top10)))
        ax1.set_yticklabels(top10['Event'])
        ax1.set_xlabel('Количество')
        ax1.set_title('Топ-10 подозрительных событий', fontsize=14, fontweight='bold')

        # Добавление значений на бары
        for i, (bar, count) in enumerate(zip(bars, top10['Count'])):
            ax1.text(count + 0.5, bar.get_y() + bar.get_height() / 2, str(int(count)),
                     va='center', fontweight='bold')

        # Легенда
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor='#ff6b6b', label='WinEventLog'),
                           Patch(facecolor='#4ecdc4', label='DNS Logs')]
        ax1.legend(handles=legend_elements, loc='lower right')

        # График 2: Распределение по источникам
        ax2 = plt.subplot(2, 2, 2)
        source_counts = df_viz.groupby('Source')['Count'].sum()
        colors_pie = ['#ff6b6b', '#4ecdc4']
        wedges, texts, autotexts = ax2.pie(source_counts.values,
                                           labels=source_counts.index,
                                           autopct='%1.1f%%',
                                           colors=colors_pie,
                                           startangle=90)
        ax2.set_title('Распределение подозрительных событий\nпо источникам',
                      fontsize=14, fontweight='bold')

        # График 3: WinEvent события по EventID (если есть)
        ax3 = plt.subplot(2, 2, 3)
        if 'WinEvent' in self.suspicious_events and self.suspicious_events['WinEvent']:
            winevent_data = pd.DataFrame(
                list(self.suspicious_events['WinEvent'].items()),
                columns=['Event', 'Count']
            ).nlargest(8, 'Count')

            # Извлекаем EventID из названия для лучшей читаемости
            winevent_data['ShortName'] = winevent_data['Event'].apply(
                lambda x: x[:40] + '...' if len(x) > 40 else x
            )

            bars = ax3.barh(range(len(winevent_data)), winevent_data['Count'], color='#ff9f9f')
            ax3.set_yticks(range(len(winevent_data)))
            ax3.set_yticklabels(winevent_data['ShortName'])
            ax3.set_xlabel('Количество')
            ax3.set_title('Подозрительные события WinEventLog', fontsize=12, fontweight='bold')

            # Добавление значений
            for i, (bar, count) in enumerate(zip(bars, winevent_data['Count'])):
                ax3.text(count + 0.5, bar.get_y() + bar.get_height() / 2, str(int(count)),
                         va='center', fontweight='bold')
        else:
            ax3.text(0.5, 0.5, 'Нет данных WinEvent',
                     ha='center', va='center', transform=ax3.transAxes)
            ax3.set_title('Подозрительные события WinEventLog', fontsize=12, fontweight='bold')

        # График 4: DNS события
        ax4 = plt.subplot(2, 2, 4)
        if 'DNS' in self.suspicious_events and self.suspicious_events['DNS']:
            dns_data = pd.DataFrame(
                list(self.suspicious_events['DNS'].items()),
                columns=['Event', 'Count']
            ).nlargest(8, 'Count')

            bars = ax4.barh(range(len(dns_data)), dns_data['Count'], color='#8fd9d9')
            ax4.set_yticks(range(len(dns_data)))
            ax4.set_yticklabels(dns_data['Event'])
            ax4.set_xlabel('Количество')
            ax4.set_title('Подозрительные события DNS', fontsize=12, fontweight='bold')

            # Добавление значений
            for i, (bar, count) in enumerate(zip(bars, dns_data['Count'])):
                ax4.text(count + 0.5, bar.get_y() + bar.get_height() / 2, str(int(count)),
                         va='center', fontweight='bold')
        else:
            ax4.text(0.5, 0.5, 'Нет данных DNS',
                     ha='center', va='center', transform=ax4.transAxes)
            ax4.set_title('Подозрительные события DNS', fontsize=12, fontweight='bold')

        plt.tight_layout()
        plt.savefig('botsv1_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("\nГрафики сохранены в 'botsv1_analysis.png'")

    def print_summary(self):
        """Вывод сводной информации"""
        print("\n" + "=" * 60)
        print("СВОДНЫЙ ОТЧЕТ ПО АНАЛИЗУ")
        print("=" * 60)

        total_suspicious = 0
        all_results = []

        for source, events in self.suspicious_events.items():
            print(f"\n{source.upper()}:")
            source_total = sum(events.values())
            total_suspicious += source_total

            # Сортируем события по убыванию
            sorted_events = sorted(events.items(), key=lambda x: x[1], reverse=True)
            for event, count in sorted_events:
                print(f"  • {event}: {count}")
                all_results.append({
                    'Source': source,
                    'Event': event,
                    'Count': count
                })
            print(f"  Всего в {source}: {source_total}")

        print(f"\nИТОГО подозрительных событий: {total_suspicious}")

        # Сохранение результатов в CSV
        if all_results:
            results_df = pd.DataFrame(all_results)
            results_df.to_csv('suspicious_events_summary.csv', index=False)
            print("\nРезультаты сохранены в 'suspicious_events_summary.csv'")

        # Дополнительная статистика по WinEvent логам
        if self.winevent_df is not None and len(self.winevent_df) > 0:
            print("\n" + "=" * 60)
            print("ДОПОЛНИТЕЛЬНАЯ СТАТИСТИКА WINEVENT")
            print("=" * 60)

            # Временной анализ
            if '_time' in self.winevent_df.columns:
                self.winevent_df['hour'] = pd.to_datetime(self.winevent_df['_time']).dt.hour
                hour_dist = self.winevent_df['hour'].value_counts().sort_index()
                print("\nРаспределение событий по часам:")
                peak_hours = hour_dist.nlargest(3)
                for hour, count in peak_hours.items():
                    print(f"  {hour:02d}:00 - {count} событий")

            # Анализ по компьютерам
            if 'ComputerName' in self.winevent_df.columns:
                computer_stats = self.winevent_df['ComputerName'].value_counts()
                print(f"\nАктивных компьютеров: {len(computer_stats)}")
                print("Топ-5 компьютеров по активности:")
                for computer, count in computer_stats.head(5).items():
                    print(f"  {computer}: {count} событий")

    def run_full_analysis(self, winevent_file, dns_file=None):
        """Запуск полного анализа"""
        print("=" * 60)
        print("АНАЛИЗ ЛОГОВ BOTSV1")
        print("=" * 60)

        # Загрузка WinEvent логов
        if self.load_winevent_data(winevent_file):
            # Анализ WinEvent логов
            self.analyze_winevent_logs()

        # Загрузка и анализ DNS логов (если указан файл)
        if dns_file:
            self.load_dns_data(dns_file)
            self.analyze_dns_logs()
        else:
            print("\nDNS логи не указаны для анализа")

        # Визуализация
        self.visualize_results()

        # Сводка
        self.print_summary()


# Основная программа
def main():
    analyzer = BotsV1Analyzer()

    winevent_file = 'botsv1.json'

    analyzer.run_full_analysis(winevent_file)


if __name__ == "__main__":
    main()
