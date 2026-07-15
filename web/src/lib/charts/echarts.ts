import * as echarts from 'echarts/core';
import {
	GaugeChart,
	LineChart,
	BarChart,
	PieChart,
	ScatterChart,
	GraphChart,
	TreeChart
} from 'echarts/charts';
import {
	TitleComponent,
	TooltipComponent,
	GridComponent,
	LegendComponent,
	VisualMapComponent
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([
	GaugeChart,
	LineChart,
	BarChart,
	PieChart,
	ScatterChart,
	GraphChart,
	TreeChart,
	TitleComponent,
	TooltipComponent,
	GridComponent,
	LegendComponent,
	VisualMapComponent,
	CanvasRenderer
]);

export { echarts };
export type { ECharts, EChartsOption } from 'echarts/core';
