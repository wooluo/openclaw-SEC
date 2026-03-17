/**
 * Assets Page
 * Asset management and scanning
 */

import React, { useState, useEffect } from 'react'
import {
  Table,
  Card,
  Button,
  Input,
  Select,
  Tag,
  Space,
  Modal,
  message,
  Tooltip,
} from 'antd'
import {
  ReloadOutlined,
  SearchOutlined,
  ScanOutlined,
  FileTextOutlined,
  CloudUploadOutlined,
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import api from '@/services/api'

const { Option } = Select

interface Asset {
  id: string
  path: string
  asset_type: string
  risk_level: string
  created_at: string
  updated_at: string
  metadata: any
}

const Assets = () => {
  const [loading, setLoading] = useState(false)
  const [assets, setAssets] = useState<Asset[]>([])
  const [filteredAssets, setFilteredAssets] = useState<Asset[]>([])
  const [stats, setStats] = useState<any>(null)
  const [searchText, setSearchText] = useState('')
  const [typeFilter, setTypeFilter] = useState<string | undefined>()
  const [riskFilter, setRiskFilter] = useState<string | undefined>()
  const [scanModalVisible, setScanModalVisible] = useState(false)

  useEffect(() => {
    fetchAssets()
    fetchStats()
  }, [])

  useEffect(() => {
    let filtered = assets

    if (searchText) {
      filtered = filtered.filter((a) =>
        a.path.toLowerCase().includes(searchText.toLowerCase())
      )
    }

    if (typeFilter) {
      filtered = filtered.filter((a) => a.asset_type === typeFilter)
    }

    if (riskFilter) {
      filtered = filtered.filter((a) => a.risk_level === riskFilter)
    }

    setFilteredAssets(filtered)
  }, [assets, searchText, typeFilter, riskFilter])

  const fetchAssets = async () => {
    setLoading(true)
    try {
      const data = await api.getAssets()
      setAssets(data)
    } catch (error) {
      message.error('加载资产失败')
    } finally {
      setLoading(false)
    }
  }

  const fetchStats = async () => {
    try {
      const data = await api.getAssetStats()
      setStats(data)
    } catch (error) {
      console.error('Failed to fetch stats:', error)
    }
  }

  const handleScan = async (directory: string) => {
    try {
      await api.scanAssets({ directory, recursive: true })
      message.success('扫描已启动')
      setScanModalVisible(false)
      fetchAssets()
      fetchStats()
    } catch (error) {
      message.error('启动扫描失败')
    }
  }

  const getRiskColor = (level: string) => {
    const colors: Record<string, string> = {
      critical: '#ff4d4f',
      high: '#ff7a45',
      medium: '#ffa940',
      low: '#52c41a',
      safe: '#1890ff',
    }
    return colors[level] || '#d9d9d9'
  }

  const columns: ColumnsType<Asset> = [
    {
      title: '路径',
      dataIndex: 'path',
      key: 'path',
      ellipsis: true,
      render: (text) => (
        <Tooltip title={text}>
          <span>{text}</span>
        </Tooltip>
      ),
    },
    {
      title: '类型',
      dataIndex: 'asset_type',
      key: 'asset_type',
      width: 100,
      render: (type) => <Tag>{type}</Tag>,
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      key: 'risk_level',
      width: 120,
      render: (level) => (
        <Tag color={getRiskColor(level)}>{level.toUpperCase()}</Tag>
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 180,
      render: (time) => new Date(time).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      width: 100,
      render: (_, record) => (
        <Space>
          <Button size="small" type="link">
            详情
          </Button>
        </Space>
      ),
    },
  ]

  const assetTypes = [...new Set(assets.map((a) => a.asset_type))]
  const riskLevels = ['critical', 'high', 'medium', 'low', 'safe']

  return (
    <div>
      <Card
        title="资产管理"
        extra={
          <Space>
            <Button icon={<CloudUploadOutlined />} onClick={() => setScanModalVisible(true)}>
              扫描目录
            </Button>
            <Button icon={<ReloadOutlined />} onClick={fetchAssets}>
              刷新
            </Button>
          </Space>
        }
      />

      {stats && (
        <Card style={{ marginTop: 16 }}>
          <Row gutter={[24, 16]}>
            <Col span={6}>
              <Statistic title="总资产" value={stats.total_assets} prefix={<FileTextOutlined />} />
            </Col>
            <Col span={6}>
              <Statistic title="高风险资产" value={stats.by_risk?.critical || 0} valueStyle={{ color: '#ff4d4f' }} />
            </Col>
            <Col span={6}>
              <Statistic title="中风险资产" value={stats.by_risk?.medium || 0} valueStyle={{ color: '#ffa940' }} />
            </Col>
            <Col span={6}>
              <Statistic title="安全资产" value={stats.by_risk?.safe || 0} valueStyle={{ color: '#52c41a' }} />
            </Col>
          </Row>
        </Card>
      )}

      <Card style={{ marginTop: 16 }}>
        <Space style={{ marginBottom: 16 }}>
          <Input
            placeholder="搜索资产路径"
            prefix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            style={{ width: 250 }}
          />
          <Select
            placeholder="资产类型"
            allowClear
            style={{ width: 150 }}
            value={typeFilter}
            onChange={setTypeFilter}
          >
            {assetTypes.map((type) => (
              <Option key={type} value={type}>
                {type}
              </Option>
            ))}
          </Select>
          <Select
            placeholder="风险等级"
            allowClear
            style={{ width: 150 }}
            value={riskFilter}
            onChange={setRiskFilter}
          >
            {riskLevels.map((level) => (
              <Option key={level} value={level}>
                {level.toUpperCase()}
              </Option>
            ))}
          </Select>
        </Space>

        <Table
          columns={columns}
          dataSource={filteredAssets}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 20, showSizeChanger: true }}
        />
      </Card>

      <Modal
        title="扫描目录"
        open={scanModalVisible}
        onCancel={() => setScanModalVisible(false)}
        onOk={() => handleScan('/path/to/scan')}
        okText="开始扫描"
      >
        <Input placeholder="输入要扫描的目录路径" prefix={<ScanOutlined />} />
      </Modal>
    </div>
  )
}

export default Assets
