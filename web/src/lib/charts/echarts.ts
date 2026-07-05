import * as echarts from 'echarts/core';
import { GaugeChart, LineChart, BarChart, PieChart, ScatterChart } from 'echarts/charts';
import {
	TitleComponent,
	TooltipComponent,
	GridComponent,
	LegendComponent
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([
	GaugeChart,
	LineChart,
	BarChart,
	PieChart,
	ScatterChart,
	TitleComponent,
	TooltipComponent,
	GridComponent,
	LegendComponent,
	CanvasRenderer
]);

export { echarts };
export type { ECharts, EChartsOption } from 'echarts/core';
