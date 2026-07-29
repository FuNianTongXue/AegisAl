import SwiftUI

struct DashboardDateRangePicker: View {
    @EnvironmentObject private var model: AppModel
    @Binding var startDate: Date
    @Binding var endDate: Date
    @State private var isPresented = false

    var body: some View {
        Button {
            isPresented.toggle()
        } label: {
            HStack(spacing: 9) {
                Image(systemName: "calendar")
                    .font(AppTypography.system(size: 13, weight: .semibold))
                    .foregroundStyle(AppPalette.primary)

                Text(calendarButtonDate(startDate))
                Image(systemName: "arrow.right")
                    .font(AppTypography.system(size: 10, weight: .semibold))
                    .foregroundStyle(AppPalette.textSubtle)
                Text(calendarButtonDate(endDate))

                Image(systemName: "chevron.down")
                    .font(AppTypography.system(size: 9, weight: .bold))
                    .foregroundStyle(AppPalette.textSubtle)
            }
            .font(AppTypography.callout.monospacedDigit().weight(.medium))
            .foregroundStyle(AppPalette.text)
            .padding(.horizontal, 11)
            .frame(height: 36)
            .background(AppPalette.card.opacity(0.78))
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.92))
            }
        }
        .buttonStyle(.plain)
        .help(model.text(.dateRangeHelp))
        .popover(isPresented: $isPresented, arrowEdge: .top) {
            RangeCalendarPopover(
                startDate: $startDate,
                endDate: $endDate,
                isPresented: $isPresented
            )
        }
    }
}

private struct RangeCalendarPopover: View {
    @EnvironmentObject private var model: AppModel
    @Binding var startDate: Date
    @Binding var endDate: Date
    @Binding var isPresented: Bool

    @State private var displayedMonth: Date
    @State private var pendingStart: Date?

    private let calendar = RangeCalendarLayout.calendar
    private let columns = Array(repeating: GridItem(.fixed(40), spacing: 0), count: 7)
    private var weekdaySymbols: [String] {
        let formatter = DateFormatter()
        formatter.locale = model.appLanguage.locale
        return formatter.veryShortWeekdaySymbols
    }

    init(startDate: Binding<Date>, endDate: Binding<Date>, isPresented: Binding<Bool>) {
        _startDate = startDate
        _endDate = endDate
        _isPresented = isPresented
        _displayedMonth = State(initialValue: RangeCalendarLayout.monthStart(for: endDate.wrappedValue))
    }

    var body: some View {
        VStack(spacing: 14) {
            monthNavigation

            LazyVGrid(columns: columns, spacing: 8) {
                ForEach(weekdaySymbols, id: \.self) { weekday in
                    Text(weekday)
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textSubtle)
                        .frame(width: 40, height: 24)
                }

                ForEach(RangeCalendarLayout.days(in: displayedMonth)) { day in
                    Button {
                        select(day.date)
                    } label: {
                        CalendarDayCell(
                            day: day,
                            startDate: startDate,
                            endDate: endDate
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(day.date > RangeCalendarLayout.today)
                    .help(calendarAccessibilityDate(day.date, locale: model.appLanguage.locale))
                }
            }
        }
        .padding(18)
        .frame(width: 324)
        .background(AppPalette.card)
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.72))
        }
        .onAppear {
            displayedMonth = RangeCalendarLayout.monthStart(for: endDate)
            pendingStart = nil
        }
    }

    private var monthNavigation: some View {
        HStack(spacing: 8) {
            Button {
                moveMonth(by: -1)
            } label: {
                Image(systemName: "chevron.left")
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .help(model.text(.previousMonth))

            Spacer(minLength: 4)

            Picker(model.text(.selectMonth), selection: monthSelection) {
                ForEach(1...availableMonthCount, id: \.self) { month in
                    Text(verbatim: monthName(month)).tag(month)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .controlSize(.regular)
            .frame(width: 80)
            .tint(AppPalette.primary)
            .help(model.text(.selectMonth))

            Picker(model.text(.selectYear), selection: yearSelection) {
                ForEach(availableYears, id: \.self) { year in
                    Text(verbatim: "\(year)").tag(year)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .controlSize(.regular)
            .frame(width: 94)
            .tint(AppPalette.primary)
            .help(model.text(.selectYear))

            Spacer(minLength: 4)

            Button {
                moveMonth(by: 1)
            } label: {
                Image(systemName: "chevron.right")
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .disabled(!canMoveToNextMonth)
            .help(model.text(.nextMonth))
        }
        .foregroundStyle(AppPalette.textMuted)
        .frame(width: 280)
    }

    private var displayedMonthNumber: Int { calendar.component(.month, from: displayedMonth) }
    private var displayedYear: Int { calendar.component(.year, from: displayedMonth) }
    private var currentMonthNumber: Int { calendar.component(.month, from: RangeCalendarLayout.today) }
    private var currentYear: Int { calendar.component(.year, from: RangeCalendarLayout.today) }
    private var availableMonthCount: Int { displayedYear == currentYear ? currentMonthNumber : 12 }
    private var availableYears: [Int] { Array((1999...currentYear).reversed()) }
    private var monthSelection: Binding<Int> {
        Binding(get: { displayedMonthNumber }, set: selectMonth)
    }
    private var yearSelection: Binding<Int> {
        Binding(get: { displayedYear }, set: selectYear)
    }

    private var canMoveToNextMonth: Bool {
        guard let next = calendar.date(byAdding: .month, value: 1, to: displayedMonth) else { return false }
        return next <= RangeCalendarLayout.monthStart(for: RangeCalendarLayout.today)
    }

    private func moveMonth(by value: Int) {
        guard let month = calendar.date(byAdding: .month, value: value, to: displayedMonth) else { return }
        displayedMonth = RangeCalendarLayout.monthStart(for: month)
    }

    private func selectMonth(_ month: Int) {
        setDisplayedMonth(year: displayedYear, month: month)
    }

    private func selectYear(_ year: Int) {
        let month = year == currentYear ? min(displayedMonthNumber, currentMonthNumber) : displayedMonthNumber
        setDisplayedMonth(year: year, month: month)
    }

    private func setDisplayedMonth(year: Int, month: Int) {
        guard let date = calendar.date(from: DateComponents(year: year, month: month, day: 1)) else { return }
        displayedMonth = RangeCalendarLayout.monthStart(for: date)
    }

    private func monthName(_ month: Int) -> String {
        let formatter = DateFormatter()
        formatter.locale = model.appLanguage.locale
        let symbols = formatter.shortMonthSymbols ?? formatter.monthSymbols ?? []
        guard month > 0, month <= symbols.count else { return "\(month)" }
        return symbols[month - 1]
    }

    private func select(_ date: Date) {
        let normalized = calendar.startOfDay(for: date)
        if let pendingStart {
            startDate = min(pendingStart, normalized)
            endDate = max(pendingStart, normalized)
            self.pendingStart = nil
            isPresented = false
        } else {
            pendingStart = normalized
            startDate = normalized
            endDate = normalized
        }
    }
}

private struct CalendarDayCell: View {
    let day: RangeCalendarDay
    let startDate: Date
    let endDate: Date

    private let calendar = RangeCalendarLayout.calendar

    private var isStart: Bool { calendar.isDate(day.date, inSameDayAs: startDate) }
    private var isEnd: Bool { calendar.isDate(day.date, inSameDayAs: endDate) }
    private var isEndpoint: Bool { isStart || isEnd }
    private var isOneDayRange: Bool { calendar.isDate(startDate, inSameDayAs: endDate) }
    private var isInRange: Bool {
        let date = calendar.startOfDay(for: day.date)
        let start = calendar.startOfDay(for: min(startDate, endDate))
        let end = calendar.startOfDay(for: max(startDate, endDate))
        return date >= start && date <= end
    }
    private var isToday: Bool { calendar.isDateInToday(day.date) }
    private var isDisabled: Bool { day.date > RangeCalendarLayout.today }

    var body: some View {
        ZStack {
            if isInRange && !isOneDayRange {
                Rectangle()
                    .fill(AppPalette.cardMuted)
                    .frame(width: 40, height: 36)
            }

            if isEndpoint {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(AppPalette.text)
                    .frame(width: 40, height: 40)
            }

            Text("\(calendar.component(.day, from: day.date))")
                .font(AppTypography.system(size: 14, weight: isEndpoint ? .semibold : .regular).monospacedDigit())
                .foregroundStyle(dayTextColor)

            if isToday {
                Circle()
                    .fill(isEndpoint ? Color.white : AppPalette.primary)
                    .frame(width: 3.5, height: 3.5)
                    .offset(y: 14)
            }
        }
        .frame(width: 40, height: 40)
        .contentShape(Rectangle())
    }

    private var dayTextColor: Color {
        if isEndpoint { return .white }
        if isDisabled { return AppPalette.textSubtle.opacity(0.38) }
        if !day.isInDisplayedMonth { return AppPalette.textSubtle.opacity(0.68) }
        return AppPalette.text
    }
}

struct RangeCalendarDay: Identifiable, Equatable {
    let date: Date
    let isInDisplayedMonth: Bool

    var id: Date { date }
}

enum RangeCalendarLayout {
    static var calendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.locale = Locale(identifier: "zh_CN")
        calendar.timeZone = .current
        calendar.firstWeekday = 1
        return calendar
    }

    static var today: Date { calendar.startOfDay(for: Date()) }

    static func monthStart(for date: Date) -> Date {
        let components = calendar.dateComponents([.year, .month], from: date)
        return calendar.date(from: components) ?? calendar.startOfDay(for: date)
    }

    static func days(in month: Date) -> [RangeCalendarDay] {
        let monthStart = monthStart(for: month)
        guard let dayRange = calendar.range(of: .day, in: .month, for: monthStart) else { return [] }
        let weekday = calendar.component(.weekday, from: monthStart)
        let leadingDays = (weekday - calendar.firstWeekday + 7) % 7
        let visibleCount = Int(ceil(Double(leadingDays + dayRange.count) / 7.0)) * 7
        guard let gridStart = calendar.date(byAdding: .day, value: -leadingDays, to: monthStart) else { return [] }

        return (0..<visibleCount).compactMap { offset in
            guard let date = calendar.date(byAdding: .day, value: offset, to: gridStart) else { return nil }
            return RangeCalendarDay(
                date: date,
                isInDisplayedMonth: calendar.isDate(date, equalTo: monthStart, toGranularity: .month)
            )
        }
    }
}

private func calendarButtonDate(_ date: Date) -> String {
    let components = RangeCalendarLayout.calendar.dateComponents([.year, .month, .day], from: date)
    return String(
        format: "%04d/%02d/%02d",
        components.year ?? 0,
        components.month ?? 0,
        components.day ?? 0
    )
}

private func calendarAccessibilityDate(_ date: Date, locale: Locale) -> String {
    let formatter = DateFormatter()
    formatter.calendar = RangeCalendarLayout.calendar
    formatter.locale = locale
    formatter.dateStyle = .long
    return formatter.string(from: date)
}
